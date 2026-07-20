/**
 * Covalent Bond Relay Client
 * Pure transport to the relay. The relay is addressed by routing ID only;
 * the session code never appears in any request. Polling loops live in
 * PollingManager, not here.
 */

import { generateSecureSessionId, validateRoutingId, auditToolCall, logger } from '../security/index.js';

export class RelayClient {
  constructor(relayUrl) {
    this.relayUrl = relayUrl || process.env.COVALENT_RELAY_URL || 'http://localhost:8787';
    this.peerId = generateSecureSessionId();
    this.currentSession = null;
    // Relay-assigned per-session sequence number of the last message seen.
    // Sequence numbers (not timestamps) drive delivery: two messages in the
    // same millisecond cannot shadow each other.
    this.lastSeq = 0;
  }

  async request(path, options) {
    const response = await fetch(`${this.relayUrl}${path}`, options);

    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error(`Relay returned invalid response (HTTP ${response.status})`);
    }

    if (!response.ok) {
      throw new Error(data.error || `Relay error (HTTP ${response.status})`);
    }

    return data;
  }

  /**
   * Create a new session on the relay.
   * @param {string} routingId - Derived routing ID (relay never sees the code)
   * @param {string} publicKey - Hex-encoded raw X25519 public key
   */
  async createSession(routingId, publicKey) {
    validateRoutingId(routingId);

    const data = await this.request('/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ routingId, publicKey, peerId: this.peerId })
    });

    this.currentSession = { routingId, publicKey, role: 'host' };
    this.lastSeq = 0;

    return data;
  }

  /**
   * Join an existing session.
   * @param {string} routingId - Derived routing ID
   * @param {string} publicKey - Our hex-encoded public key
   * @returns {Promise<Object>} Response with host's publicKey
   */
  async joinSession(routingId, publicKey) {
    validateRoutingId(routingId);

    const data = await this.request('/join', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ routingId, publicKey, peerId: this.peerId })
    });

    this.currentSession = {
      routingId,
      publicKey,
      hostPublicKey: data.hostPublicKey,
      role: 'guest'
    };
    this.lastSeq = 0;

    return data;
  }

  /**
   * Send an encrypted payload to the session.
   * @param {Object} encryptedPayload - { v, iv, encrypted, authTag }
   */
  async send(encryptedPayload) {
    if (!this.currentSession) {
      throw new Error('Not connected to any session');
    }

    await this.request('/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        routingId: this.currentSession.routingId,
        fromPeerId: this.peerId,
        encryptedPayload
      })
    });
  }

  /**
   * Poll for new messages.
   * @returns {Promise<Array>} Array of raw (still encrypted) messages
   */
  async poll() {
    if (!this.currentSession) {
      return [];
    }

    const url = new URL(`${this.relayUrl}/poll`);
    url.searchParams.set('routingId', this.currentSession.routingId);
    url.searchParams.set('peerId', this.peerId);
    url.searchParams.set('since', this.lastSeq.toString());

    const data = await this.request(url.pathname + url.search, {});

    // The relay reports the oldest seq it still retains. If messages we never
    // received were pruned (queue cap under bursty traffic), delivery is no
    // longer complete; surface it instead of fast-forwarding silently.
    if (typeof data.oldestSeq === 'number' && this.lastSeq > 0 &&
        this.lastSeq + 1 < data.oldestSeq) {
      const missed = data.oldestSeq - this.lastSeq - 1;
      logger.warn(`Relay pruned ${missed} message(s) before delivery; the stream has a gap`);
      auditToolCall('relay_gap_detected', { missed }, 'security');
      this.lastSeq = data.oldestSeq - 1;
    }

    if (data.messages.length > 0) {
      this.lastSeq = Math.max(this.lastSeq, ...data.messages.map(m => m.seq || 0));
    }

    if (data.disconnected) {
      this.currentSession = null;
      logger.info('Session disconnected');
    }

    return data.messages;
  }

  /**
   * Disconnect from current session.
   */
  async disconnect() {
    if (!this.currentSession) {
      return;
    }

    await this.request('/disconnect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        routingId: this.currentSession.routingId,
        peerId: this.peerId
      })
    });

    this.currentSession = null;
  }

  getSession() {
    return this.currentSession;
  }

  getPeerId() {
    return this.peerId;
  }

  async healthCheck() {
    try {
      const response = await fetch(`${this.relayUrl}/health`);
      const data = await response.json();
      return data.status === 'ok';
    } catch (error) {
      logger.error('Relay health check failed:', error.message);
      return false;
    }
  }
}
