/**
 * Mock Relay Server for Testing
 * Implements same API as Cloudflare Worker but runs locally
 */

import http from 'http';
import { pathToFileURL } from 'url';
import {
  SESSION_TTL_MS, MAX_MESSAGES, MAX_PEERS,
  SEND_WINDOW_MS, SEND_MAX, IP_WINDOW_MS, IP_MAX,
  PAYLOAD_LIMITS, POLL_MAX_BYTES, ERROR_CODES as SHARED_ERROR_CODES
} from '../relay/constants.js';

// Peer IDs and raw X25519 public keys are both 32 bytes hex-encoded.
const HEX_64 = /^[0-9a-f]{64}$/;

// Mirror of the worker's per-message storage semantics: seq-ordered queue,
// oldestSeq tracking on prune, poll response budget.
function pushMessage(session, from, payload) {
  const message = { from, seq: session.nextSeq++, payload, timestamp: Date.now() };
  session.messages.push(message);
  while (session.nextSeq - session.oldestSeq > MAX_MESSAGES) {
    session.oldestSeq++;
  }
  session.messages = session.messages.filter(m => m.seq >= session.oldestSeq);
  return message;
}

// In-memory session storage
const sessions = new Map();

// Rate limiting storage (in-memory)
const rateLimits = new Map();

const RATE_LIMITS = {
  perIP: { windowMs: IP_WINDOW_MS, maxRequests: IP_MAX },
  perSession: { windowMs: SEND_WINDOW_MS, maxRequests: SEND_MAX }
};

// Error codes (shared source of truth)
const ERROR_CODES = SHARED_ERROR_CODES;

// SECURITY: Security headers applied to all responses
function getSecurityHeaders() {
  return {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'",
    'Referrer-Policy': 'no-referrer'
  };
}

function checkRateLimit(key, limit) {
  const now = Date.now();
  const rateLimitKey = `ratelimit:${key}`;

  // Get current rate limit data
  let requestLog = rateLimits.get(rateLimitKey) || { requests: [] };

  // Remove requests outside the time window
  const windowStart = now - limit.windowMs;
  requestLog.requests = requestLog.requests.filter(timestamp => timestamp > windowStart);

  // Check if limit exceeded
  if (requestLog.requests.length >= limit.maxRequests) {
    return {
      allowed: false,
      retryAfter: Math.ceil((requestLog.requests[0] + limit.windowMs - now) / 1000)
    };
  }

  // Add current request
  requestLog.requests.push(now);

  // Store updated log
  rateLimits.set(rateLimitKey, requestLog);

  // Cleanup old entries periodically
  if (Math.random() < 0.01) {
    for (const [key, log] of rateLimits.entries()) {
      log.requests = log.requests.filter(timestamp => timestamp > now - limit.windowMs);
      if (log.requests.length === 0) {
        rateLimits.delete(key);
      }
    }
  }

  return { allowed: true };
}

const server = http.createServer((req, res) => {
  // No CORS headers on purpose: the relay serves native MCP clients, not
  // browsers. Allowing cross-origin requests would only invite abuse.
  Object.entries(getSecurityHeaders()).forEach(([key, value]) => {
    res.setHeader(key, value);
  });

  const url = new URL(req.url, `http://${req.headers.host}`);

  // SECURITY: Per-IP rate limiting (except health endpoint)
  if (url.pathname !== '/health') {
    const clientIP = req.socket.remoteAddress || 'unknown';
    const ipRateLimit = checkRateLimit(`ip:${clientIP}`, RATE_LIMITS.perIP);

    if (!ipRateLimit.allowed) {
      res.writeHead(429, {
        'Content-Type': 'application/json',
        'Retry-After': ipRateLimit.retryAfter.toString()
      });
      res.end(JSON.stringify({
        error: 'Rate limit exceeded',
        retryAfter: ipRateLimit.retryAfter
      }));
      return;
    }
  }

  // Parse request body for POST requests
  if (req.method === 'POST') {
    let body = '';
    let bodySize = 0;
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);

    // Determine payload limit based on endpoint
    let maxSize = 10 * 1024; // Default 10KB
    if (url.pathname === '/send') {
      maxSize = PAYLOAD_LIMITS.send;
    } else if (url.pathname === '/create') {
      maxSize = PAYLOAD_LIMITS.create;
    } else if (url.pathname === '/join') {
      maxSize = PAYLOAD_LIMITS.join;
    } else if (url.pathname === '/disconnect') {
      maxSize = PAYLOAD_LIMITS.disconnect;
    }

    // Check Content-Length header first
    if (contentLength > maxSize) {
      return jsonResponse(res, {
        error: 'Request payload too large',
        code: ERROR_CODES.PAYLOAD_TOO_LARGE,
        maxSize
      }, 413);
    }

    req.on('data', chunk => {
      bodySize += chunk.length;
      if (bodySize > maxSize) {
        req.destroy();
        return jsonResponse(res, {
          error: 'Request payload too large',
          code: ERROR_CODES.PAYLOAD_TOO_LARGE,
          maxSize
        }, 413);
      }
      body += chunk;
    });

    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        handleRequest(url.pathname, data, res);
      } catch (error) {
        console.error('Parse error:', error);
        jsonResponse(res, {
          error: 'An internal error occurred',
          code: 'ERR_INTERNAL_ERROR'
        }, 500);
      }
    });
  } else {
    handleRequest(url.pathname, url.searchParams, res);
  }
});

function handleRequest(path, data, res) {
  if (path === '/create') {
    return handleCreate(data, res);
  }
  if (path === '/join') {
    return handleJoin(data, res);
  }
  if (path === '/send') {
    return handleSend(data, res);
  }
  if (path === '/poll') {
    return handlePoll(data, res);
  }
  if (path === '/disconnect') {
    return handleDisconnect(data, res);
  }
  if (path === '/health') {
    return jsonResponse(res, { status: 'ok', timestamp: Date.now() });
  }

  jsonResponse(res, { error: 'Not found' }, 404);
}

function handleCreate(data, res) {
  const { routingId, publicKey, peerId } = data;

  if (!routingId) {
    return jsonResponse(res, {
      error: 'Missing required fields',
      code: ERROR_CODES.MISSING_FIELDS
    }, 400);
  }

  // Routing ID: 64 hex chars (PBKDF2-derived; relay never sees the session code)
  if (!HEX_64.test(routingId)) {
    return jsonResponse(res, {
      error: 'Invalid routing ID format',
      code: ERROR_CODES.INVALID_SESSION_CODE
    }, 400);
  }

  // The creator's peerId is required (an empty peer list could be filled by
  // two arbitrary parties) and keys must be raw 32-byte X25519 keys (hex).
  if (!HEX_64.test(publicKey || '') || !HEX_64.test(peerId || '')) {
    return jsonResponse(res, {
      error: 'Missing required fields',
      code: ERROR_CODES.MISSING_FIELDS
    }, 400);
  }

  // A live session already claims this routing ID; refuse to clobber it.
  const existing = sessions.get(routingId);
  if (existing && existing.expiresAt > Date.now()) {
    return jsonResponse(res, {
      error: 'Session is full',
      code: ERROR_CODES.SESSION_FULL
    }, 403);
  }

  const now = Date.now();
  const expiresAt = now + SESSION_TTL_MS;

  const session = {
    routingId,
    hostPublicKey: publicKey,
    createdAt: now,
    expiresAt,
    peers: [peerId],                // creator is always the first peer
    messages: [],
    nextSeq: 1,                     // relay-assigned message ordering
    oldestSeq: 1                    // seq of the oldest message still retained
  };

  sessions.set(routingId, session);

  console.log(`✅ Created session: ${routingId}${peerId ? ` (host: ${peerId.substring(0, 8)}...)` : ''}`);

  jsonResponse(res, { ok: true, routingId, expiresAt });
}

function handleJoin(data, res) {
  const { routingId, publicKey, peerId } = data;

  if (!routingId || !HEX_64.test(publicKey || '') || !HEX_64.test(peerId || '')) {
    return jsonResponse(res, {
      error: 'Missing required fields',
      code: ERROR_CODES.MISSING_FIELDS
    }, 400);
  }

  const session = sessions.get(routingId);

  if (!session) {
    return jsonResponse(res, {
      error: 'Session not found',
      code: ERROR_CODES.SESSION_NOT_FOUND
    }, 404);
  }

  if (session.expiresAt < Date.now()) {
    sessions.delete(routingId);
    return jsonResponse(res, {
      error: 'Session expired',
      code: ERROR_CODES.SESSION_EXPIRED
    }, 410);
  }

  if (session.peers.length >= MAX_PEERS) {
    return jsonResponse(res, {
      error: 'Session is full',
      code: ERROR_CODES.SESSION_FULL
    }, 403);
  }

  // Store joiner's public key
  session.joinerPublicKey = publicKey;

  if (!session.peers.includes(peerId)) {
    session.peers.push(peerId);

    // Notify host about joiner's public key
    pushMessage(session, 'system', { type: 'peer_joined', peerId, publicKey });

    console.log(`✅ Peer ${peerId.substring(0, 8)}... joined session ${routingId}`);
  }

  jsonResponse(res, {
    ok: true,
    hostPublicKey: session.hostPublicKey,  // Return host's public key
    peerCount: session.peers.length
  });
}

function handleSend(data, res) {
  const { routingId, fromPeerId, encryptedPayload } = data;

  if (!routingId || !fromPeerId || !encryptedPayload) {
    return jsonResponse(res, {
      error: 'Missing required fields',
      code: ERROR_CODES.MISSING_FIELDS
    }, 400);
  }

  // SECURITY: Per-session rate limiting (10 messages/minute)
  const sessionRateLimit = checkRateLimit(
    `session:${routingId}:${fromPeerId}`,
    RATE_LIMITS.perSession
  );

  if (!sessionRateLimit.allowed) {
    res.writeHead(429, {
      'Content-Type': 'application/json',
      'Retry-After': sessionRateLimit.retryAfter.toString()
    });
    res.end(JSON.stringify({
      error: 'Rate limit exceeded',
      code: ERROR_CODES.RATE_LIMIT_EXCEEDED,
      retryAfter: sessionRateLimit.retryAfter
    }));
    return;
  }

  const session = sessions.get(routingId);

  if (!session) {
    return jsonResponse(res, {
      error: 'Session not found',
      code: ERROR_CODES.SESSION_NOT_FOUND
    }, 404);
  }

  if (!session.peers.includes(fromPeerId)) {
    return jsonResponse(res, {
      error: 'Unauthorized access',
      code: ERROR_CODES.UNAUTHORIZED
    }, 403);
  }

  pushMessage(session, fromPeerId, encryptedPayload);
  session.expiresAt = Date.now() + SESSION_TTL_MS;

  console.log(`📤 Message from ${fromPeerId.substring(0, 8)}... in ${routingId}`);

  jsonResponse(res, { ok: true });
}

function handlePoll(params, res) {
  const routingId = params.get('routingId');
  const peerId = params.get('peerId');
  const since = parseInt(params.get('since') || '0', 10);

  if (!routingId || !peerId) {
    return jsonResponse(res, {
      error: 'Missing required fields',
      code: ERROR_CODES.MISSING_FIELDS
    }, 400);
  }

  const session = sessions.get(routingId);

  if (!session) {
    return jsonResponse(res, { messages: [], disconnected: true });
  }

  if (!session.peers.includes(peerId)) {
    return jsonResponse(res, {
      error: 'Unauthorized access',
      code: ERROR_CODES.UNAUTHORIZED
    }, 403);
  }

  // Polling is activity too: a connected-but-quiet pair must not expire
  // mid-session. Refresh at most once a minute (mirrors the worker).
  if (session.expiresAt - Date.now() < SESSION_TTL_MS - 60000) {
    session.expiresAt = Date.now() + SESSION_TTL_MS;
  }

  // Deliver in seq order under the response byte budget (always at least
  // one message); oldestSeq lets the client detect pruned deliveries.
  const messages = [];
  let bytes = 0;
  for (const msg of session.messages) {
    if (msg.from === peerId || msg.seq <= since) continue;
    const size = JSON.stringify(msg).length;
    if (messages.length > 0 && bytes + size > POLL_MAX_BYTES) break;
    bytes += size;
    messages.push(msg);
  }

  if (messages.length > 0) {
    console.log(`📥 ${messages.length} message(s) for ${peerId.substring(0, 8)}...`);
  }

  jsonResponse(res, { messages, disconnected: false, oldestSeq: session.oldestSeq });
}

function handleDisconnect(data, res) {
  const { routingId, peerId } = data;

  if (!routingId || !peerId) {
    return jsonResponse(res, {
      error: 'Missing required fields',
      code: ERROR_CODES.MISSING_FIELDS
    }, 400);
  }

  const session = sessions.get(routingId);

  if (!session) {
    return jsonResponse(res, { ok: true });
  }

  // Membership gate mirrors the production worker: non-members cannot spoof
  // departures or flood the queue through the unthrottled disconnect path.
  if (!session.peers.includes(peerId)) {
    return jsonResponse(res, { ok: true });
  }

  session.peers = session.peers.filter(p => p !== peerId);

  pushMessage(session, 'system', { type: 'disconnect', peerId });

  if (session.peers.length === 0) {
    sessions.delete(routingId);
    console.log(`❌ Session ${routingId} deleted (no peers left)`);
  }

  console.log(`👋 Peer ${peerId.substring(0, 8)}... disconnected from ${routingId}`);

  jsonResponse(res, { ok: true });
}

function jsonResponse(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

const PORT = 8787;

/**
 * Start the mock relay (for in-process use by tests).
 * @param {number} port
 * @returns {Promise<http.Server>}
 */
export function startMockRelay(port = PORT) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

export function stopMockRelay() {
  return new Promise((resolve) => server.close(resolve));
}

/** Test hook: wipe all relay state between suites. */
export function resetMockRelay() {
  sessions.clear();
  rateLimits.clear();
}

// Run standalone: node test/mock-relay-server.js
// (pathToFileURL handles Windows paths; a naive string compare does not)
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startMockRelay().then(() => {
    console.log(`🚀 Mock Relay Server running on http://localhost:${PORT}`);
    console.log('Ready for connection tests...\n');
  });
}
