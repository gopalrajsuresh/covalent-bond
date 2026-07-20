/**
 * Payload hardening test, against the in-process mock relay.
 * Verifies size limits, error sanitization, standardized error codes,
 * and security headers using routing IDs.
 */

import assert from 'assert';
import crypto from 'crypto';
import { startMockRelay, stopMockRelay, resetMockRelay } from './mock-relay-server.js';
import { PAYLOAD_LIMITS } from '../relay/constants.js';

const PORT = 8793;
const RELAY_URL = `http://127.0.0.1:${PORT}`;

// Helpers for valid values
const routingId = () => crypto.randomBytes(32).toString('hex');
const pubKey = () => crypto.randomBytes(32).toString('hex');

console.log('🛡️ Testing Payload Hardening\n');

await startMockRelay(PORT);
resetMockRelay();

const post = (path, body) => fetch(`${RELAY_URL}${path}`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body)
});

// ============================================================================
console.log('Test 1: /create rejects oversized payload (10 KB limit)');
const bigCreate = await post('/create', {
  routingId: routingId(),
  publicKey: 'x'.repeat(15 * 1024),
  peerId: 'p'
});
assert.strictEqual(bigCreate.status, 413);
const bigCreateData = await bigCreate.json();
assert.ok(bigCreateData.code?.startsWith('ERR_'), 'must return standardized error code');
console.log('✅ oversized /create rejected\n');

// ============================================================================
console.log('Test 2: /send rejects oversized payload (5 MB limit)');
const rid = routingId();
await post('/create', { routingId: rid, publicKey: pubKey(), peerId: crypto.randomBytes(32).toString('hex') });
const bigSend = await post('/send', {
  routingId: rid,
  fromPeerId: 'host',
  encryptedPayload: { iv: 'x', encrypted: 'x'.repeat(6 * 1024 * 1024), authTag: 'x' }
});
assert.strictEqual(bigSend.status, 413);
console.log('✅ oversized /send rejected\n');

// ============================================================================
console.log('Test 2b: a worst-case max-size file stays under the relay /send cap');
{
  // The 384 KB ceiling must survive the full wire expansion even for
  // pathological content (every byte JSON-escapes to \uXXXX, then hex).
  const { encrypt } = await import('../daemon/crypto.js');
  const key = crypto.randomBytes(32).toString('hex');
  const worst = ''.repeat(384 * 1024);           // 384 KB, all control chars
  const packet = JSON.stringify({ type: 'file_transfer', content: worst, ts: 1 });
  const encrypted = encrypt(packet, key);
  const wireBytes = Buffer.byteLength(JSON.stringify(encrypted));
  assert.ok(wireBytes < PAYLOAD_LIMITS.send,
    `worst-case 384 KB file serializes to ${wireBytes} bytes, must be < ${PAYLOAD_LIMITS.send}`);

  const rid2 = routingId();
  const hostPeer = crypto.randomBytes(32).toString('hex');
  await post('/create', { routingId: rid2, publicKey: pubKey(), peerId: hostPeer });
  const okSend = await post('/send', { routingId: rid2, fromPeerId: hostPeer, encryptedPayload: encrypted });
  assert.strictEqual(okSend.status, 200, 'a max-size worst-case file must be accepted by the relay');
}
console.log('✅ max-size worst-case file fits the wire\n');

// ============================================================================
console.log('Test 3: error messages are sanitized');
const notFound = await post('/join', { routingId: routingId(), publicKey: pubKey(), peerId: crypto.randomBytes(32).toString('hex') });
const notFoundData = await notFound.json();
const leaks = /stack|file:\/\/|\.js:|\bat \b/.test(notFoundData.error) || notFoundData.error.length > 100;
assert.ok(!leaks, `error message leaks internals: "${notFoundData.error}"`);
console.log(`✅ sanitized: "${notFoundData.error}"\n`);

// ============================================================================
console.log('Test 4: standardized error codes');
const cases = [
  { url: '/create', body: { routingId: routingId() }, code: 'ERR_MISSING_FIELDS' },
  { url: '/create', body: { routingId: 'not-hex', publicKey: pubKey() }, code: 'ERR_INVALID_SESSION_CODE' },
  { url: '/join', body: { routingId: routingId(), publicKey: pubKey(), peerId: crypto.randomBytes(32).toString('hex') }, code: 'ERR_SESSION_NOT_FOUND' }
];
for (const c of cases) {
  const res = await post(c.url, c.body);
  const data = await res.json();
  assert.strictEqual(data.code, c.code, `${c.url}: expected ${c.code}, got ${data.code}`);
  console.log(`✅ ${c.code}`);
}
console.log();

// ============================================================================
console.log('Test 5: security headers present on all responses');
const required = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'content-security-policy': "default-src 'none'",
  'referrer-policy': 'no-referrer'
};
const health = await fetch(`${RELAY_URL}/health`);
for (const [name, expected] of Object.entries(required)) {
  assert.strictEqual((health.headers.get(name) || '').toLowerCase(), expected.toLowerCase(),
    `missing/incorrect header: ${name}`);
}
console.log('✅ all security headers present\n');

await stopMockRelay();

console.log('═══════════════════════════════════════════');
console.log('✅ payload-hardening.test.js PASSED');
console.log('═══════════════════════════════════════════');
