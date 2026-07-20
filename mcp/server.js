/**
 * Covalent Bond MCP Server
 * Exposes bond_* tools to the MCP client over the Model Context Protocol.
 *
 * IMPORTANT: stdout carries the MCP JSON-RPC stream. Nothing in this
 * process tree may write to stdout; all logging goes to stderr via
 * `logger` (see security/index.js).
 *
 * Events that arrive between tool calls (peer joined, incoming transfer,
 * handshake results) are queued and delivered appended to the next tool
 * response, and are always visible via bond_status.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { TOOLS, validateToolArgs } from './tools.js';
import {
  generateConsentPrompt,
  generateAcceptSuccess,
  generateDeclineConfirmation,
  generateStatusMessage,
  generateConnectionSuccess,
  generateSendSuccess,
  generateDisconnectConfirmation,
  generateErrorMessage
} from './consent-ui.js';

import { SessionManager } from '../daemon/session-manager.js';
import { RelayClient } from '../relay/client.js';
import { PollingManager } from '../relay/poll.js';
import { FileSender } from '../transfer/sender.js';
import { FileReceiver } from '../transfer/receiver.js';
import { generateKeypair, deriveRoutingId } from '../daemon/crypto.js';
import {
  logger,
  auditToolCall,
  sanitizeForContext,
  detectInjectionPatterns,
  wrapUntrustedContent
} from '../security/index.js';
import { notifyDesktop } from './notify.js';
import { readFileSync } from 'fs';

// Inbound chat display cap: mirrors the bond_message send limit. Anything
// longer is truncated for display (the peer's client enforces 4000 too, but
// a modified client can skip that; never trust inbound sizes).
const CHAT_MAX_CHARS = 4000;

// Single source of truth for the version is package.json.
export const SERVER_VERSION = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8')
).version;

class CovalentBondServer {
  constructor(relayUrl) {
    this.server = new Server(
      { name: 'covalent', version: SERVER_VERSION },
      { capabilities: { tools: {} } }
    );

    this.relayUrl = relayUrl;
    this.sessionManager = new SessionManager();
    this.relayClient = new RelayClient(relayUrl);
    this.fileSender = null;
    this.fileReceiver = new FileReceiver();
    this.pendingNotifications = [];

    this.pollingManager = new PollingManager(this.relayClient, this.sessionManager, {
      onConfirmed: (_session) => {
        this.queueNotification(
          '🔐 Secure channel established: peer verified knowledge of the session code. ' +
          'File transfers are now allowed.'
        );
        notifyDesktop('connected', '');
      },
      onConfirmFailed: (reason) => {
        this.queueNotification(
          `🚨 SESSION ABORTED: ${reason}\n` +
          'The session was terminated before any data was exchanged. ' +
          'If this repeats, the relay may be compromised or the session code was mistyped.'
        );
      },
      onFileTransfer: async (packet, fromPeerId) => {
        try {
          const consentData = this.fileReceiver.processIncomingTransfer(packet, fromPeerId);
          this.queueNotification(generateConsentPrompt(consentData));
          notifyDesktop('file', fromPeerId, {
            filename: packet.filename,
            sizeFormatted: consentData.preview && consentData.preview.sizeFormatted
          });
        } catch (error) {
          this.queueNotification(`⚠️ Incoming transfer rejected: ${error.message}`);
        }
      },
      onChat: (packet, fromPeerId) => {
        // Peer text is untrusted data: validate the shape, sanitize, scan,
        // and wrap it exactly like file content before it enters the context.
        if (typeof packet.content !== 'string' || packet.content.length === 0) {
          logger.warn('Dropped malformed chat packet (non-string or empty content)');
          auditToolCall('chat_dropped_malformed', { from: fromPeerId.substring(0, 8) }, 'security');
          return;
        }
        let text = packet.content;
        let truncated = '';
        if (text.length > CHAT_MAX_CHARS) {
          text = text.slice(0, CHAT_MAX_CHARS).replace(/[\uD800-\uDBFF]$/, '');
          truncated = `\n[Message truncated at ${CHAT_MAX_CHARS} characters]`;
        }
        const sanitized = sanitizeForContext(text);
        const findings = detectInjectionPatterns(sanitized);
        this.queueNotification(
          `💬 Message from peer ${fromPeerId.substring(0, 8)}...:\n` +
          wrapUntrustedContent(sanitized, findings) + truncated
        );
        notifyDesktop('message', fromPeerId);
      },
      onPeerDisconnect: (peerId) => {
        // Reflect reality in the session state so bond_status doesn't keep
        // reporting an established channel with 2 peers after the peer left.
        // Note: the disconnect notice is an unauthenticated relay system
        // message, so a malicious relay could fabricate it, but that only
        // fail-closes this side (blocks sends until bond_end), which the
        // relay could achieve anyway by dropping traffic.
        const session = this.sessionManager.getCurrentSession();
        if (session) {
          session.peerCount = Math.max(1, (session.peerCount || 2) - 1);
          session.peerDisconnected = true;
        }
        auditToolCall('peer_disconnected', {
          peer: (peerId || '').substring(0, 8)
        }, 'system');
        this.queueNotification(
          '👋 Peer disconnected from the session. Use bond_end to close this side.'
        );
        notifyDesktop('disconnect', peerId);
      }
    });

    this.setupHandlers();

    this.server.onerror = (error) => {
      logger.error('[MCP Server Error]', error.message || String(error));
    };

    process.on('SIGINT', async () => {
      await this.cleanup();
      process.exit(0);
    });
  }

  queueNotification(text) {
    this.pendingNotifications.push(text);
  }

  /**
   * Drain queued event notifications into a tool response so the agent
   * sees events that arrived between tool calls.
   */
  drainNotifications() {
    if (this.pendingNotifications.length === 0) {
      return '';
    }

    const block = [
      '',
      '═══════════════════════════════════════════',
      '📨 Events since last tool call:',
      '═══════════════════════════════════════════',
      ...this.pendingNotifications
    ].join('\n');

    this.pendingNotifications = [];
    return block;
  }

  setupHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: TOOLS,
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) =>
      this.handleToolCall(request)
    );
  }

  async handleToolCall(request) {
    const { name, arguments: args } = request.params;

    try {
      const validation = validateToolArgs(name, args || {});
      if (!validation.valid) {
        return {
          content: [{ type: 'text', text: generateErrorMessage(name, validation.error) }],
          isError: true,
        };
      }

      let result;
      switch (name) {
        case 'bond_connect':
          result = await this.handleConnect();
          break;
        case 'bond_join':
          result = await this.handleJoin(args.sessionCode);
          break;
        case 'bond_send':
          result = await this.handleSend(args.filepath, args.message);
          break;
        case 'bond_message':
          result = await this.handleMessage(args.content);
          break;
        case 'bond_wait':
          result = await this.handleWait(args.timeoutSeconds);
          break;
        case 'bond_accept':
          result = await this.handleAccept(args.transferId);
          break;
        case 'bond_decline':
          result = await this.handleDecline(args.transferId);
          break;
        case 'bond_status':
          result = await this.handleStatus();
          break;
        case 'bond_end':
          result = await this.handleEnd();
          break;
        default:
          throw new Error(`Unknown tool: ${name}`);
      }

      return {
        content: [{ type: 'text', text: result + this.drainNotifications() }],
      };
    } catch (error) {
      logger.error(`Tool ${name} failed:`, error.message);
      return {
        content: [{ type: 'text', text: generateErrorMessage(name, error) + this.drainNotifications() }],
        isError: true,
      };
    }
  }

  /**
   * bond_connect - Create new session as host.
   * Polling starts immediately: the key exchange completes automatically
   * when the guest joins, followed by mutual key confirmation.
   */
  async handleConnect() {
    if (this.sessionManager.getCurrentSession()) {
      throw new Error('Already in a session - use bond_end first');
    }

    const session = this.sessionManager.createSession();
    await this.relayClient.createSession(session.routingId, session.publicKey);

    this.fileSender = new FileSender(this.relayClient, this.sessionManager);
    this.pollingManager.start();

    auditToolCall('session_created', {
      role: 'host',
      routing: session.routingId.substring(0, 12)
    }, 'user');

    return generateConnectionSuccess(session.code, true);
  }

  /**
   * bond_join - Join existing session as guest.
   */
  async handleJoin(sessionCode) {
    if (this.sessionManager.getCurrentSession()) {
      throw new Error('Already in a session - use bond_end first');
    }

    // Keypair is generated BEFORE the relay join because our public key is
    // part of the join request; the same keypair then derives the session key.
    const keypair = generateKeypair();
    const routingId = deriveRoutingId(sessionCode);

    const joinResult = await this.relayClient.joinSession(
      routingId,
      keypair.publicKey.toString('hex')
    );

    let confirmationTag;
    try {
      ({ confirmationTag } = this.sessionManager.joinSession(
        sessionCode,
        joinResult.hostPublicKey,
        keypair
      ));
    } catch (err) {
      // The relay already counted us as a peer; leave so the session isn't
      // stuck at SESSION_FULL for the legitimate guest until TTL expiry.
      await this.relayClient.disconnect().catch(() => {});
      throw err;
    }

    this.fileSender = new FileSender(this.relayClient, this.sessionManager);
    this.pollingManager.start();

    // Prove knowledge of the session key to the host. The host replies
    // with its own confirmation; the session is usable once that arrives.
    await this.pollingManager.sendKeyConfirmation(confirmationTag);

    auditToolCall('session_joined', {
      role: 'guest',
      routing: routingId.substring(0, 12)
    }, 'user');

    return generateConnectionSuccess(sessionCode, false);
  }

  /**
   * bond_send - Send file to peer (requires confirmed session).
   */
  async handleSend(filepath, message = '') {
    if (!this.fileSender) {
      throw new Error('Not connected to session - use bond_connect or bond_join first');
    }

    const session = this.sessionManager.getCurrentSession();
    if (session && session.peerDisconnected) {
      throw new Error('Peer has disconnected - nobody would receive this file. Use bond_end to close the session');
    }

    const result = await this.fileSender.sendFile(filepath, message);
    return generateSendSuccess(result, message);
  }

  /**
   * bond_message - Send an encrypted text message to the peer.
   * Requires a confirmed session; refused after the peer disconnects.
   */
  async handleMessage(content) {
    const session = this.sessionManager.getCurrentSession();
    if (!session) {
      throw new Error('Not connected to session - use bond_connect or bond_join first');
    }
    if (session.peerDisconnected) {
      throw new Error('Peer has disconnected - nobody would receive this message. Use bond_end to close the session');
    }
    if (!this.sessionManager.isConfirmed()) {
      throw new Error('Session key not confirmed yet - wait for the peer handshake to complete');
    }

    // Messages share the same per-session send cooldown as files, so a
    // wait/reply loop (or a modified client) cannot flood the relay.
    if (this.fileSender) {
      const rate = this.fileSender.checkRateLimit(session.code);
      if (!rate.allowed) {
        throw new Error(`Rate limit: please wait ${rate.wait} seconds before sending again`);
      }
    }

    await this.pollingManager.sendEncrypted({ type: 'chat', content });
    if (this.fileSender) {
      this.fileSender.updateRateLimit(session.code);
    }
    auditToolCall('bond_message', { chars: content.length }, 'user');

    return [
      '═══════════════════════════════════════════',
      '💬 Message Sent',
      '═══════════════════════════════════════════',
      '',
      `Delivered encrypted to the peer (${content.length} characters).`,
      'Use bond_wait to listen for the reply, or bond_status to check later.',
      ''
    ].join('\n');
  }

  /**
   * bond_wait - Block until the next peer event arrives or the timeout
   * passes. The background poller keeps receiving; this only watches the
   * local event queue, so waiting adds no relay traffic. The queued events
   * themselves are appended to the response by drainNotifications().
   */
  async handleWait(timeoutSeconds = 50) {
    if (!this.sessionManager.getCurrentSession()) {
      throw new Error('Not connected to session - use bond_connect or bond_join first');
    }

    const clamped = Math.min(Math.max(timeoutSeconds || 50, 1), 300);
    const deadline = Date.now() + clamped * 1000;

    while (Date.now() < deadline) {
      if (this.pendingNotifications.length > 0) {
        return '📨 Event received while waiting:';
      }
      if (!this.sessionManager.getCurrentSession()) {
        return '⚠️ The session ended while waiting (expired or aborted).';
      }
      await new Promise(resolve => setTimeout(resolve, 250));
    }

    return this.pendingNotifications.length > 0
      ? '📨 Event received while waiting:'
      : `No new events within ${clamped}s. The channel stays open: call bond_wait again to keep listening, or do other work and check bond_status later.`;
  }

  /**
   * bond_accept - Accept pending transfer (explicit user consent).
   */
  async handleAccept(transferId) {
    const result = await this.fileReceiver.acceptTransfer(transferId);
    return generateAcceptSuccess(result) + '\n' + result.injectionText;
  }

  /**
   * bond_decline - Decline pending transfer.
   */
  async handleDecline(transferId) {
    const result = this.fileReceiver.declineTransfer(transferId);
    return generateDeclineConfirmation(result);
  }

  /**
   * bond_status - Connection status, handshake state, pending transfers.
   */
  async handleStatus() {
    const session = this.sessionManager.getCurrentSession();
    const pendingTransfers = this.fileReceiver.getPendingTransfers();

    return generateStatusMessage(session, pendingTransfers, this.pendingNotifications.length);
  }

  /**
   * bond_end - Disconnect from session.
   */
  async handleEnd() {
    const hadSession = !!this.sessionManager.getCurrentSession();
    this.pollingManager.stop();
    await this.relayClient.disconnect();
    this.sessionManager.clearSession();
    this.fileReceiver.clearPendingTransfers();
    this.fileSender = null;

    if (hadSession) {
      auditToolCall('session_ended', { reason: 'user' }, 'user');
    }

    return generateDisconnectConfirmation();
  }

  async cleanup() {
    this.pollingManager.stop();

    if (this.relayClient) {
      try {
        await this.relayClient.disconnect();
      } catch { /* relay may be unreachable during shutdown */ }
    }

    this.fileReceiver.clearPendingTransfers();
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    logger.info('Covalent Bond MCP server running on stdio');
  }
}

import { pathToFileURL } from 'url';
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = new CovalentBondServer();
  server.run().catch((error) => logger.error('Fatal:', error.message));
}

export { CovalentBondServer };
