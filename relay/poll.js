/**
 * Covalent Bond Polling Manager
 *
 * Owns the poll loop and the session protocol state machine:
 *  - completes the host side of the key exchange when the guest joins
 *  - performs mutual key confirmation before any transfer is allowed
 *  - decrypts and dispatches application messages (file transfers, chat)
 *
 * Any decryption or confirmation failure aborts the session: with the
 * key schedule that failure is exactly what a key-substituting relay
 * (MITM) produces.
 */

import { decrypt, encrypt, generateNonce, validateNonceAndTimestamp } from '../daemon/crypto.js';
import { auditToolCall, logger } from '../security/index.js';

const POLL_INTERVAL_MS = 5000;

export class PollingManager {
  /**
   * @param {RelayClient} relayClient
   * @param {SessionManager} sessionManager
   * @param {Object} handlers - {
   *   onConfirmed(session),
   *   onConfirmFailed(reason),
   *   onFileTransfer(packet, fromPeerId),
   *   onChat(message, fromPeerId),
   *   onPeerDisconnect(peerId)
   * }
   */
  constructor(relayClient, sessionManager, handlers = {}) {
    this.relayClient = relayClient;
    this.sessionManager = sessionManager;
    this.handlers = handlers;
    this.pollingInterval = null;
    this.isPolling = false;
  }

  start() {
    if (this.isPolling) {
      return;
    }

    this.isPolling = true;
    this.pollingInterval = setInterval(() => {
      this.pollOnce().catch(error => {
        logger.error('Polling error:', error.message);
      });
    }, POLL_INTERVAL_MS);

    logger.info(`Started polling (${POLL_INTERVAL_MS / 1000}s interval)`);
  }

  stop() {
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
      this.pollingInterval = null;
    }

    this.isPolling = false;
  }

  isActive() {
    return this.isPolling;
  }

  /**
   * Encrypt and send a protocol message to the peer.
   * @param {Object} packet - Plain object; gets nonce + timestamp added
   */
  async sendEncrypted(packet) {
    const session = this.sessionManager.getCurrentSession();

    if (!session || !session.sessionKey) {
      throw new Error('No keyed session - cannot send');
    }

    const full = { nonce: generateNonce(), timestamp: Date.now(), ...packet };
    await this.relayClient.send(encrypt(JSON.stringify(full), session.sessionKey));
    this.sessionManager.refreshSession(session.code);
  }

  /**
   * Send our key-confirmation tag to the peer.
   */
  async sendKeyConfirmation(confirmationTag) {
    const session = this.sessionManager.getCurrentSession();
    await this.sendEncrypted({
      type: 'key_confirm',
      role: session.role,
      tag: confirmationTag
    });
  }

  async pollOnce() {
    if (!this.relayClient.getSession()) {
      // Nothing to poll (never connected, or the relay reported the session
      // gone). Stop the interval so an ended session cannot leak a poller.
      this.stop();
      return;
    }

    // A host confirmation whose send failed (relay 429, network blip) is
    // retried here; otherwise the handshake deadlocks with the guest
    // waiting forever for our tag.
    if (this.pendingHostConfirmation && this.sessionManager.isConfirmed()) {
      try {
        await this.sendKeyConfirmation(this.pendingHostConfirmation);
        this.pendingHostConfirmation = null;
      } catch (error) {
        logger.warn(`Key confirmation resend failed; will retry: ${error.message}`);
      }
    }

    const messages = await this.relayClient.poll();

    for (const message of messages) {
      await this.handleMessage(message);
    }

    // Once the peer has left, sends are refused and nothing further can
    // arrive; keeping the interval alive would only refresh the relay TTL
    // of a dead session and burn requests until bond_end.
    const session = this.sessionManager.getCurrentSession();
    if (session && session.peerDisconnected) {
      logger.info('Peer disconnected - stopping poll loop');
      this.stop();
    }
  }

  async handleMessage(message) {
    if (message.from === 'system') {
      await this.handleSystemMessage(message);
      return;
    }

    const session = this.sessionManager.getCurrentSession();

    if (!session || !session.sessionKey) {
      logger.warn('Received peer message before key exchange completed; ignoring');
      return;
    }

    let packet;
    try {
      packet = JSON.parse(decrypt(message.payload, session.sessionKey));
    } catch (error) {
      // Before key confirmation, a decrypt failure means the peer derived a
      // different key: the signature of a relay MITM (or a wrong session
      // code). Abort rather than limp along.
      //
      // AFTER confirmation the peer has already proven the shared key, so
      // garbage ciphertext can only be relay-injected junk. Aborting then
      // would hand a malicious relay a one-message session-teardown lever
      // (the same reasoning that makes replays drop, not abort), so drop it
      // and leave an audit trail instead.
      if (this.sessionManager.isConfirmed()) {
        logger.warn(`Dropped undecryptable packet from confirmed session: ${error.message}`);
        auditToolCall('packet_dropped_undecryptable', { reason: error.message }, 'security');
        return;
      }
      await this.abortSession(`Failed to decrypt peer message: ${error.message}`);
      return;
    }

    // Replay protection for EVERY packet type. A replayed packet is dropped,
    // not aborted on: aborting would let a malicious relay tear the session
    // down at will just by replaying old ciphertext.
    try {
      validateNonceAndTimestamp(packet.nonce, packet.timestamp);
    } catch (error) {
      logger.warn(`Dropped replayed/stale packet (${packet.type}): ${error.message}`);
      auditToolCall('packet_dropped_replay', { type: packet.type, reason: error.message }, 'security');
      return;
    }

    // Peer traffic decrypted under the session key: the session is live,
    // so extend its lifetime.
    this.sessionManager.refreshSession(session.code);

    switch (packet.type) {
      case 'key_confirm':
        await this.handleKeyConfirm(packet, session);
        break;

      case 'file_transfer':
        if (!this.sessionManager.isConfirmed()) {
          await this.abortSession('File transfer received before key confirmation');
          return;
        }
        if (this.handlers.onFileTransfer) {
          await this.handlers.onFileTransfer(packet, message.from);
        }
        break;

      case 'chat':
        if (!this.sessionManager.isConfirmed()) {
          await this.abortSession('Chat received before key confirmation');
          return;
        }
        if (this.handlers.onChat) {
          await this.handlers.onChat(packet, message.from);
        }
        break;

      default:
        logger.warn(`Unknown packet type from peer: ${packet.type}`);
    }
  }

  async handleSystemMessage(message) {
    const { payload } = message;

    if (payload.type === 'peer_joined') {
      const session = this.sessionManager.getCurrentSession();

      if (session && session.role === 'host' && session.state === 'waiting') {
        // Complete key exchange with the guest's public key. Our own
        // confirmation tag is sent only AFTER the guest proves knowledge
        // of the session key (see handleKeyConfirm).
        try {
          const { confirmationTag } = this.sessionManager.completeKeyExchange(
            session.code,
            payload.publicKey
          );
          this.pendingHostConfirmation = confirmationTag;
          auditToolCall('key_exchange_completed', { role: 'host' }, 'system');
        } catch (error) {
          await this.abortSession(`Key exchange failed: ${error.message}`);
        }
      }
      return;
    }

    if (payload.type === 'disconnect') {
      logger.info(`Peer ${String(payload.peerId).substring(0, 8)}... disconnected`);
      if (this.handlers.onPeerDisconnect) {
        this.handlers.onPeerDisconnect(payload.peerId);
      }
    }
  }

  async handleKeyConfirm(packet, session) {
    const ok = this.sessionManager.confirmPeer(session.code, packet.tag);

    if (!ok) {
      await this.abortSession('Peer key confirmation FAILED - possible MITM at relay');
      return;
    }

    auditToolCall('key_confirmed', { peerRole: packet.role }, 'system');

    // Host replies with its own confirmation once the guest is verified.
    // A failed send must not lose the tag: pollOnce retries it until it
    // goes through (the guest is stuck in 'keyed' until then).
    if (session.role === 'host' && this.pendingHostConfirmation) {
      try {
        await this.sendKeyConfirmation(this.pendingHostConfirmation);
        this.pendingHostConfirmation = null;
      } catch (error) {
        logger.warn(`Key confirmation send failed; will retry on next poll: ${error.message}`);
      }
    }

    if (this.handlers.onConfirmed) {
      await this.handlers.onConfirmed(this.sessionManager.getCurrentSession());
    }
  }

  /**
   * Abort the session on any protocol/security failure.
   */
  async abortSession(reason) {
    logger.error(`Session aborted: ${reason}`);
    auditToolCall('session_aborted', { reason }, 'security');

    this.stop();

    try {
      await this.relayClient.disconnect();
    } catch { /* relay may already be gone */ }

    this.sessionManager.clearSession();

    if (this.handlers.onConfirmFailed) {
      this.handlers.onConfirmFailed(reason);
    }
  }
}
