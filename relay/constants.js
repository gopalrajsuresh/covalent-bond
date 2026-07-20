/**
 * Shared relay protocol constants.
 *
 * The real relay (cloudflare-worker/worker.js) and the in-process mock relay
 * (test/mock-relay-server.js) MUST agree on these values, or tests pass
 * against behavior the deployed relay does not have. This module is the one
 * source of truth; both sides import it so the two implementations can never
 * silently drift.
 *
 * The Cloudflare Worker cannot import from outside its own directory at
 * deploy time, so worker.js keeps its own copy, but `relay-parity.test.js`
 * asserts, by reading both files, that every value here matches the worker's.
 */

export const SESSION_TTL_MS = 30 * 60 * 1000;   // session lifetime after last activity
export const MAX_MESSAGES = 100;                // per-session message queue cap
export const MAX_PEERS = 2;                     // host + guest, no third party

// Per-session send throttle (per peer).
export const SEND_WINDOW_MS = 60 * 1000;
export const SEND_MAX = 10;

// Optional per-IP throttle (mock enforces it; the worker delegates to an
// optional Cloudflare rate-limit binding).
export const IP_WINDOW_MS = 60 * 1000;
export const IP_MAX = 100;

// Poll responses stop adding messages once this many payload bytes are
// queued in one response; the client's next poll (by seq) picks up the rest.
// At least one message is always returned, so delivery never stalls.
export const POLL_MAX_BYTES = 1 * 1024 * 1024;

// Payload size caps, in bytes, per endpoint.
export const PAYLOAD_LIMITS = {
  create: 10 * 1024,
  join: 10 * 1024,
  send: 5 * 1024 * 1024,
  disconnect: 1 * 1024
};

export const ERROR_CODES = {
  PAYLOAD_TOO_LARGE: 'ERR_PAYLOAD_TOO_LARGE',
  RATE_LIMIT_EXCEEDED: 'ERR_RATE_LIMIT_EXCEEDED',
  INVALID_SESSION_CODE: 'ERR_INVALID_SESSION_CODE',
  SESSION_NOT_FOUND: 'ERR_SESSION_NOT_FOUND',
  SESSION_EXPIRED: 'ERR_SESSION_EXPIRED',
  SESSION_FULL: 'ERR_SESSION_FULL',
  UNAUTHORIZED: 'ERR_UNAUTHORIZED',
  MISSING_FIELDS: 'ERR_MISSING_FIELDS'
};
