/**
 * Covalent Bond Relay - Cloudflare Worker + Durable Objects
 *
 * A "dumb pipe" that routes encrypted messages between two agents.
 * - Stores ONLY routing IDs, public keys, and ciphertext (never plaintext,
 *   never the session code)
 * - One Durable Object per routing ID: strongly consistent, single-threaded
 *   state. No KV, no read-modify-write races, no eventual-consistency lag.
 * - Sessions expire 30 minutes after last activity (alarm-driven cleanup)
 * - Max 2 peers per session
 * - Messages carry a relay-assigned sequence number; clients poll by seq,
 *   so same-millisecond messages can never shadow each other.
 */

// These mirror relay/constants.js. The Worker can't import across directories
// at deploy time, so it keeps its own copies; test/relay-parity.test.js reads
// this file and fails if any value drifts from the shared source of truth.
const SESSION_TTL_MS = 30 * 60 * 1000;
const MAX_MESSAGES = 100;
const MAX_PEERS = 2;
const POLL_MAX_BYTES = 1 * 1024 * 1024;

// Durable Object storage caps a single value at 128 KiB. Messages are stored
// one per key (never inside the session record), and any message larger than
// this is split across chunk keys, so a max-size /send can never hit the cap.
const CHUNK_SIZE = 64 * 1024;

// Peer IDs and raw X25519 public keys are both 32 bytes hex-encoded.
const HEX_64 = /^[0-9a-f]{64}$/;

// Per-session send throttle (enforced inside the DO, in memory)
const SEND_LIMIT = { windowMs: 60000, maxRequests: 10 };

// Payload size limits (in bytes), enforced on the actual body read;
// a missing Content-Length header cannot bypass them.
const PAYLOAD_LIMITS = {
  '/create': 10 * 1024,
  '/join': 10 * 1024,
  '/send': 5 * 1024 * 1024,
  '/disconnect': 1 * 1024
};

const ERROR_CODES = {
  PAYLOAD_TOO_LARGE: 'ERR_PAYLOAD_TOO_LARGE',
  RATE_LIMIT_EXCEEDED: 'ERR_RATE_LIMIT_EXCEEDED',
  INVALID_SESSION_CODE: 'ERR_INVALID_SESSION_CODE',
  SESSION_NOT_FOUND: 'ERR_SESSION_NOT_FOUND',
  SESSION_EXPIRED: 'ERR_SESSION_EXPIRED',
  SESSION_FULL: 'ERR_SESSION_FULL',
  UNAUTHORIZED: 'ERR_UNAUTHORIZED',
  MISSING_FIELDS: 'ERR_MISSING_FIELDS'
};

// No CORS headers on purpose: the relay serves native MCP clients, not
// browsers. Allowing cross-origin requests would only invite abuse.
function securityHeaders() {
  return {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'",
    'Referrer-Policy': 'no-referrer'
  };
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...securityHeaders(),
      ...extraHeaders
    }
  });
}

function payloadTooLarge(maxSize) {
  return jsonResponse({
    error: 'Request payload too large',
    code: ERROR_CODES.PAYLOAD_TOO_LARGE,
    maxSize
  }, 413);
}

/**
 * Read and JSON-parse a request body with a hard byte cap enforced on the
 * bytes actually received, not the Content-Length header.
 * @returns {{ok: true, body: Object} | {ok: false, response: Response}}
 */
async function readJsonBody(request, maxSize) {
  const declared = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (declared > maxSize) {
    return { ok: false, response: payloadTooLarge(maxSize) };
  }

  const reader = request.body ? request.body.getReader() : null;
  if (!reader) {
    return { ok: false, response: jsonResponse({ error: 'Missing body', code: ERROR_CODES.MISSING_FIELDS }, 400) };
  }

  const chunks = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maxSize) {
      await reader.cancel();
      return { ok: false, response: payloadTooLarge(maxSize) };
    }
    chunks.push(value);
  }

  try {
    const buf = new Uint8Array(received);
    let offset = 0;
    for (const c of chunks) { buf.set(c, offset); offset += c.byteLength; }
    return { ok: true, body: JSON.parse(new TextDecoder().decode(buf)) };
  } catch {
    return { ok: false, response: jsonResponse({ error: 'Invalid JSON body', code: ERROR_CODES.MISSING_FIELDS }, 400) };
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === '/health') {
        return jsonResponse({ status: 'ok', timestamp: Date.now() });
      }

      // Optional per-IP throttle via a Workers rate-limiting binding.
      // The per-session limits inside the DO are the primary protection;
      // this is belt-and-braces if the binding is configured.
      if (env.IP_LIMITER) {
        const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
        const { success } = await env.IP_LIMITER.limit({ key: ip });
        if (!success) {
          return jsonResponse({
            error: 'Rate limit exceeded',
            code: ERROR_CODES.RATE_LIMIT_EXCEEDED
          }, 429, { 'Retry-After': '60' });
        }
      }

      let routingId;
      let body = null;

      if (request.method === 'POST' && PAYLOAD_LIMITS[path]) {
        const read = await readJsonBody(request, PAYLOAD_LIMITS[path]);
        if (!read.ok) return read.response;
        body = read.body;
        routingId = body.routingId;
      } else if (path === '/poll' && request.method === 'GET') {
        routingId = url.searchParams.get('routingId');
      } else {
        return jsonResponse({ error: 'Endpoint not found', code: 'ERR_NOT_FOUND' }, 404);
      }

      // Validate routing ID before it becomes a DO name (HashDoS protection).
      // The relay never sees the session code; only this PBKDF2-derived ID.
      if (!routingId || !/^[0-9a-f]{64}$/.test(routingId)) {
        return jsonResponse({
          error: 'Invalid routing ID format',
          code: ERROR_CODES.INVALID_SESSION_CODE
        }, 400);
      }

      // One Durable Object per routing ID: all session state lives there.
      const stub = env.SESSION_DO.get(env.SESSION_DO.idFromName(routingId));
      const doUrl = new URL(request.url);
      const init = body
        ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
        : { method: 'GET' };
      return await stub.fetch(doUrl.toString(), init);
    } catch (error) {
      // SECURITY: Sanitize error messages - never expose internal details
      console.error('Internal error:', error);
      return jsonResponse({ error: 'An internal error occurred', code: 'ERR_INTERNAL_ERROR' }, 500);
    }
  }
};

/**
 * One session, one object. The DO's single-threaded execution makes every
 * handler an atomic read-modify-write, with no races between /send, /join, and
 * /poll. State is persisted so the session survives evictions, and an alarm
 * deletes everything at expiry.
 */
export class SessionDO {
  constructor(state) {
    this.state = state;
    this.session = null;          // in-memory copy (null when absent)
    this.loaded = false;          // whether we've read storage this lifetime
    this.sendLog = new Map();     // peerId -> [timestamps] (throttle; memory only)
  }

  async loadSession() {
    if (!this.loaded) {
      this.session = (await this.state.storage.get('session')) || null;
      this.loaded = true;
    }
    return this.session;
  }

  async saveSession() {
    await this.state.storage.put('session', this.session);
    // Expiry follows last activity; the alarm hard-deletes all state.
    await this.state.storage.setAlarm(this.session.expiresAt);
  }

  // Zero-padded so lexicographic key order equals numeric seq order.
  msgKey(seq) {
    return `msg:${String(seq).padStart(10, '0')}`;
  }

  /**
   * Store one message under its own key(s). Small messages inline their JSON
   * in the meta record; large ones split into chunk keys. All keys for one
   * message are written in a single atomic put.
   * @returns {number} the assigned sequence number
   */
  async pushMessage(from, payload) {
    const seq = this.session.nextSeq++;
    const json = JSON.stringify({ from, seq, payload, timestamp: Date.now() });
    const entries = {};
    if (json.length <= CHUNK_SIZE) {
      entries[this.msgKey(seq)] = { chunks: 0, json };
    } else {
      const chunks = Math.ceil(json.length / CHUNK_SIZE);
      entries[this.msgKey(seq)] = { chunks };
      for (let i = 0; i < chunks; i++) {
        entries[`${this.msgKey(seq)}:${i}`] = json.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
      }
    }
    await this.state.storage.put(entries);

    // Queue cap: drop the oldest message(s). oldestSeq is reported to
    // pollers so a client can detect that undelivered messages were pruned.
    while (this.session.nextSeq - this.session.oldestSeq > MAX_MESSAGES) {
      await this.deleteMessage(this.session.oldestSeq++);
    }
    return seq;
  }

  async deleteMessage(seq) {
    const meta = await this.state.storage.get(this.msgKey(seq));
    const keys = [this.msgKey(seq)];
    if (meta && meta.chunks > 0) {
      for (let i = 0; i < meta.chunks; i++) keys.push(`${this.msgKey(seq)}:${i}`);
    }
    await this.state.storage.delete(keys);
  }

  async readMessage(seq) {
    const meta = await this.state.storage.get(this.msgKey(seq));
    if (!meta) return null;
    let json = meta.json;
    if (meta.chunks > 0) {
      const keys = [];
      for (let i = 0; i < meta.chunks; i++) keys.push(`${this.msgKey(seq)}:${i}`);
      const map = await this.state.storage.get(keys);
      json = keys.map(k => map.get(k)).join('');
    }
    return { message: JSON.parse(json), bytes: json.length };
  }

  async alarm() {
    const session = await this.loadSession();
    if (session && session.expiresAt > Date.now()) {
      // Activity extended the session after the alarm was scheduled
      await this.state.storage.setAlarm(session.expiresAt);
      return;
    }
    await this.state.storage.deleteAll();
    this.session = null;
  }

  async fetch(request) {
    const url = new URL(request.url);

    switch (url.pathname) {
      case '/create': return this.handleCreate(await request.json());
      case '/join': return this.handleJoin(await request.json());
      case '/send': return this.handleSend(await request.json());
      case '/poll': return this.handlePoll(url.searchParams);
      case '/disconnect': return this.handleDisconnect(await request.json());
      default:
        return jsonResponse({ error: 'Endpoint not found', code: 'ERR_NOT_FOUND' }, 404);
    }
  }

  expired(session) {
    return session.expiresAt < Date.now();
  }

  touch() {
    this.session.expiresAt = Date.now() + SESSION_TTL_MS;
  }

  async handleCreate(body) {
    const { routingId, publicKey, peerId } = body;

    // The creator's peerId is required: a session with an empty peer list
    // could be filled by two arbitrary parties. Public keys must be raw
    // 32-byte X25519 keys (hex); never store unbounded junk.
    if (!HEX_64.test(publicKey || '') || !HEX_64.test(peerId || '')) {
      return jsonResponse({ error: 'Missing required fields', code: ERROR_CODES.MISSING_FIELDS }, 400);
    }

    const existing = await this.loadSession();
    if (existing && !this.expired(existing)) {
      // A live session already claims this routing ID; refuse to clobber it.
      return jsonResponse({ error: 'Session is full', code: ERROR_CODES.SESSION_FULL }, 403);
    }
    if (existing) {
      // Expired leftovers (including message keys) must not leak into the
      // new session.
      await this.state.storage.deleteAll();
    }

    const now = Date.now();
    this.session = {
      routingId,
      hostPublicKey: publicKey,   // public key only - safe to store
      createdAt: now,
      expiresAt: now + SESSION_TTL_MS,
      peers: [peerId],
      nextSeq: 1,
      oldestSeq: 1                // seq of the oldest message still retained
    };
    await this.saveSession();

    return jsonResponse({ ok: true, routingId, expiresAt: this.session.expiresAt });
  }

  async handleJoin(body) {
    const { publicKey, peerId } = body;

    if (!HEX_64.test(publicKey || '') || !HEX_64.test(peerId || '')) {
      return jsonResponse({ error: 'Missing required fields', code: ERROR_CODES.MISSING_FIELDS }, 400);
    }

    const session = await this.loadSession();
    if (!session) {
      return jsonResponse({ error: 'Session not found', code: ERROR_CODES.SESSION_NOT_FOUND }, 404);
    }
    if (this.expired(session)) {
      await this.state.storage.deleteAll();
      this.session = null;
      return jsonResponse({ error: 'Session expired', code: ERROR_CODES.SESSION_EXPIRED }, 410);
    }

    if (!session.peers.includes(peerId)) {
      if (session.peers.length >= MAX_PEERS) {
        return jsonResponse({ error: 'Session is full', code: ERROR_CODES.SESSION_FULL }, 403);
      }

      session.peers.push(peerId);
      await this.pushMessage('system', { type: 'peer_joined', peerId, publicKey });
      this.touch();
      await this.saveSession();
    }

    return jsonResponse({
      ok: true,
      hostPublicKey: session.hostPublicKey,
      peerCount: session.peers.length
    });
  }

  throttled(peerId) {
    const now = Date.now();
    const log = (this.sendLog.get(peerId) || []).filter(t => t > now - SEND_LIMIT.windowMs);
    if (log.length >= SEND_LIMIT.maxRequests) {
      this.sendLog.set(peerId, log);
      return Math.ceil((log[0] + SEND_LIMIT.windowMs - now) / 1000);
    }
    log.push(now);
    this.sendLog.set(peerId, log);
    return 0;
  }

  async handleSend(body) {
    const { fromPeerId, encryptedPayload } = body;

    if (!fromPeerId || !encryptedPayload) {
      return jsonResponse({ error: 'Missing required fields', code: ERROR_CODES.MISSING_FIELDS }, 400);
    }

    const session = await this.loadSession();
    if (!session || this.expired(session)) {
      return jsonResponse({ error: 'Session not found', code: ERROR_CODES.SESSION_NOT_FOUND }, 404);
    }
    if (!session.peers.includes(fromPeerId)) {
      return jsonResponse({ error: 'Unauthorized access', code: ERROR_CODES.UNAUTHORIZED }, 403);
    }

    const retryAfter = this.throttled(fromPeerId);
    if (retryAfter > 0) {
      return jsonResponse({
        error: 'Rate limit exceeded',
        code: ERROR_CODES.RATE_LIMIT_EXCEEDED,
        retryAfter
      }, 429, { 'Retry-After': retryAfter.toString() });
    }

    await this.pushMessage(fromPeerId, encryptedPayload);   // relay sees ONLY ciphertext
    this.touch();
    await this.saveSession();

    return jsonResponse({ ok: true });
  }

  async handlePoll(params) {
    const peerId = params.get('peerId');
    const since = parseInt(params.get('since') || '0', 10);

    if (!peerId) {
      return jsonResponse({ error: 'Missing required fields', code: ERROR_CODES.MISSING_FIELDS }, 400);
    }

    const session = await this.loadSession();
    if (!session || this.expired(session)) {
      return jsonResponse({ messages: [], disconnected: true });
    }
    if (!session.peers.includes(peerId)) {
      return jsonResponse({ error: 'Unauthorized access', code: ERROR_CODES.UNAUTHORIZED }, 403);
    }

    // Polling is activity too: a connected-but-quiet pair must not expire
    // mid-session and look like a peer disconnect. Refresh at most once a
    // minute to keep storage writes off the 5-second poll path.
    if (session.expiresAt - Date.now() < SESSION_TTL_MS - 60000) {
      this.touch();
      await this.saveSession();
    }

    // Deliver in seq order, stopping once the response budget is spent
    // (always at least one message). oldestSeq lets the client detect that
    // the queue cap pruned messages it never received.
    const messages = [];
    let bytes = 0;
    for (let seq = Math.max(since + 1, session.oldestSeq); seq < session.nextSeq; seq++) {
      const read = await this.readMessage(seq);
      if (!read || read.message.from === peerId) continue;
      if (messages.length > 0 && bytes + read.bytes > POLL_MAX_BYTES) break;
      bytes += read.bytes;
      messages.push(read.message);
    }
    return jsonResponse({ messages, disconnected: false, oldestSeq: session.oldestSeq });
  }

  async handleDisconnect(body) {
    const { peerId } = body;

    if (!peerId) {
      return jsonResponse({ error: 'Missing required fields', code: ERROR_CODES.MISSING_FIELDS }, 400);
    }

    const session = await this.loadSession();
    if (!session) {
      return jsonResponse({ ok: true });
    }

    if (this.expired(session)) {
      await this.state.storage.deleteAll();
      this.session = null;
      return jsonResponse({ ok: true });
    }

    // Only a current member may disconnect: a stranger who knows the routing
    // ID must not be able to spoof departures or flood the message queue
    // (this path bypasses the per-peer send throttle).
    if (!session.peers.includes(peerId)) {
      return jsonResponse({ ok: true });
    }

    session.peers = session.peers.filter(p => p !== peerId);

    if (session.peers.length === 0) {
      await this.state.storage.deleteAll();
      this.session = null;
    } else {
      await this.pushMessage('system', { type: 'disconnect', peerId });
      await this.saveSession();
    }

    return jsonResponse({ ok: true });
  }
}
