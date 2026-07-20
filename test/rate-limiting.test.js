/**
 * Rate limiting test, against the in-process mock relay.
 * Verifies per-session (10 msg/min) and per-IP request throttling.
 */

import assert from 'assert';
import crypto from 'crypto';
import { startMockRelay, stopMockRelay, resetMockRelay } from './mock-relay-server.js';

const PORT = 8794;
const RELAY_URL = `http://127.0.0.1:${PORT}`;

const routingId = () => crypto.randomBytes(32).toString('hex');
const pubKey = () => crypto.randomBytes(32).toString('hex');
const post = (path, body) => fetch(`${RELAY_URL}${path}`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body)
});

console.log('🛡️ Testing Rate Limiting\n');

await startMockRelay(PORT);
resetMockRelay();

// ============================================================================
console.log('Test 1: per-session rate limit (10 messages/minute)');
const rid = routingId();
const peerId = crypto.randomBytes(32).toString('hex');
await post('/create', { routingId: rid, publicKey: pubKey(), peerId });

let sent = 0;
let limited = false;
for (let i = 0; i < 15; i++) {
  const res = await post('/send', {
    routingId: rid,
    fromPeerId: peerId,
    encryptedPayload: { iv: 'x', encrypted: 'y', authTag: 'z' }
  });
  if (res.status === 429) {
    limited = true;
    const data = await res.json();
    assert.ok(data.code === 'ERR_RATE_LIMIT_EXCEEDED' || data.error, 'must include rate-limit error');
    assert.ok(res.headers.get('retry-after'), 'must include Retry-After header');
    break;
  }
  if (res.ok) sent++;
}
assert.ok(limited, 'rate limit must trigger within 15 sends');
assert.ok(sent >= 10, `expected ~10 messages before limit, got ${sent}`);
console.log(`✅ per-session limit enforced after ${sent} messages\n`);

// ============================================================================
console.log('Test 2: per-IP rate limit (100 requests/minute)');
resetMockRelay(); // clear the per-session counter's IP budget too
let ipOk = 0;
let ipLimited = false;
for (let i = 0; i < 130; i++) {
  const res = await post('/create', { routingId: routingId(), publicKey: pubKey(), peerId: crypto.randomBytes(32).toString('hex') });
  if (res.status === 429) { ipLimited = true; break; }
  if (res.ok) ipOk++;
}
assert.ok(ipLimited, 'per-IP limit must trigger within 130 requests');
assert.ok(ipOk >= 90 && ipOk <= 100, `expected ~100 requests before limit, got ${ipOk}`);
console.log(`✅ per-IP limit enforced after ${ipOk} requests\n`);

await stopMockRelay();

console.log('═══════════════════════════════════════════');
console.log('✅ rate-limiting.test.js PASSED');
console.log('═══════════════════════════════════════════');
