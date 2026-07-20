/**
 * Tests: crypto primitives and session manager key exchange.
 * Runs fully offline (no relay).
 */

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import os from 'os';

import {
  generateKeypair,
  validatePublicKey,
  deriveSharedSecret,
  deriveRoutingId,
  deriveCodeKey,
  deriveSessionKey,
  transcriptHash,
  keyConfirmationTag,
  verifyKeyConfirmation,
  generateNonce,
  validateNonceAndTimestamp,
  encrypt,
  decrypt,
  verifyCrypto
} from '../daemon/crypto.js';

import { generateSessionCode, SessionManager } from '../daemon/session-manager.js';

console.log('🧪 Running crypto + session tests...\n');

// ============================================================================
console.log('Test 1: X25519 keypair generation');
const kp1 = generateKeypair();
const kp2 = generateKeypair();
assert.strictEqual(kp1.publicKey.length, 32, 'public key must be 32 bytes');
assert.strictEqual(kp1.privateKey.length, 32, 'private key must be 32 bytes');
assert.notStrictEqual(kp1.publicKey.toString('hex'), kp2.publicKey.toString('hex'));
validatePublicKey(kp1.publicKey);
assert.throws(() => validatePublicKey(Buffer.alloc(32)), /all-zero/);
assert.throws(() => validatePublicKey(Buffer.alloc(31, 1)), /length/);
console.log('✅ keypairs OK\n');

// ============================================================================
console.log('Test 2: shared secret symmetry');
const secretA = deriveSharedSecret(kp1.privateKey, kp2.publicKey);
const secretB = deriveSharedSecret(kp2.privateKey, kp1.publicKey);
assert.ok(secretA.equals(secretB), 'both sides must derive the same secret');
console.log('✅ X25519 agreement OK\n');

// ============================================================================
console.log('Test 3: routing ID is deterministic and code cannot be read from it');
const code = generateSessionCode();
const rid1 = deriveRoutingId(code);
const rid2 = deriveRoutingId(code);
assert.strictEqual(rid1, rid2, 'routing ID must be deterministic');
assert.match(rid1, /^[0-9a-f]{64}$/);
assert.ok(!rid1.includes(code.replace(/-/g, '')), 'routing ID must not embed the code');
assert.notStrictEqual(deriveRoutingId(generateSessionCode()), rid1);
console.log('✅ routing ID OK\n');

// ============================================================================
console.log('Test 4: session key requires BOTH the DH secret AND the code key');
const codeKey = deriveCodeKey(code);
const transcript = transcriptHash(kp1.publicKey, kp2.publicKey);
const keyHost = deriveSessionKey(secretA, codeKey, transcript);
const keyGuest = deriveSessionKey(secretB, codeKey, transcript);
assert.ok(keyHost.equals(keyGuest), 'peers must derive the same session key');

const wrongCodeKey = deriveCodeKey(generateSessionCode());
assert.ok(!deriveSessionKey(secretA, wrongCodeKey, transcript).equals(keyHost),
  'different code => different key');

const otherTranscript = transcriptHash(kp2.publicKey, kp1.publicKey);
assert.ok(!deriveSessionKey(secretA, codeKey, otherTranscript).equals(keyHost),
  'different transcript => different key');
console.log('✅ session key derivation OK\n');

// ============================================================================
console.log('Test 5: key confirmation accepts the right tag, rejects wrong ones');
const guestTag = keyConfirmationTag(keyGuest, 'guest', transcript);
assert.ok(verifyKeyConfirmation(keyHost, 'guest', transcript, guestTag));
assert.ok(!verifyKeyConfirmation(keyHost, 'host', transcript, guestTag),
  'role is bound into the tag');
const attackerKey = deriveSessionKey(secretA, wrongCodeKey, transcript);
const attackerTag = keyConfirmationTag(attackerKey, 'guest', transcript);
assert.ok(!verifyKeyConfirmation(keyHost, 'guest', transcript, attackerTag),
  'tag from a key derived without the code must fail');
assert.ok(!verifyKeyConfirmation(keyHost, 'guest', transcript, 'zz-not-hex'));
console.log('✅ key confirmation OK\n');

// ============================================================================
console.log('Test 6: AES-256-GCM round trip, tamper detection, wrong key');
const msg = 'Hello Covalent Bond - secret payload';
const box = encrypt(msg, keyHost);
assert.strictEqual(decrypt(box, keyGuest), msg);

const tampered = { ...box, encrypted: box.encrypted.replace(/^../, 'ff') };
assert.throws(() => decrypt(tampered, keyGuest), /.+/, 'tampered ciphertext must fail');

assert.throws(() => decrypt(box, attackerKey), /.+/, 'wrong key must fail');
console.log('✅ encryption OK\n');

// ============================================================================
console.log('Test 7: replay protection');
const nonce = generateNonce();
validateNonceAndTimestamp(nonce, Date.now());
assert.throws(() => validateNonceAndTimestamp(nonce, Date.now()), /replay/i,
  'same nonce twice must be rejected');
assert.throws(
  () => validateNonceAndTimestamp(generateNonce(), Date.now() - 10 * 60 * 1000),
  /timestamp/i,
  'stale timestamp must be rejected'
);
console.log('✅ replay protection OK\n');

// ============================================================================
console.log('Test 8: full offline handshake through SessionManager');
const hostSM = new SessionManager();
const guestSM = new SessionManager();

const hostSession = hostSM.createSession();
assert.strictEqual(hostSession.state, 'waiting');
assert.match(hostSession.routingId, /^[0-9a-f]{64}$/);

// Guest joins using the host's public key (as delivered by the relay)
const guestKeypair = generateKeypair();
const { session: guestSession, confirmationTag: guestConfirm } =
  guestSM.joinSession(hostSession.code, hostSession.publicKey, guestKeypair);
assert.strictEqual(guestSession.state, 'keyed');

// Host completes with the guest's public key (as delivered by the relay)
const { session: hostKeyed, confirmationTag: hostConfirm } =
  hostSM.completeKeyExchange(hostSession.code, guestSession.publicKey);
assert.strictEqual(hostKeyed.sessionKey, guestSession.sessionKey,
  'both sides must derive the same session key');
assert.ok(!hostKeyed.privateKey, 'host private key must be wiped after key derivation');
assert.ok(!hostKeyed.codeKey, 'code key must be wiped after key derivation');

// Mutual confirmation
assert.ok(hostSM.confirmPeer(hostSession.code, guestConfirm), 'host must accept guest tag');
assert.ok(guestSM.confirmPeer(hostSession.code, hostConfirm), 'guest must accept host tag');
assert.strictEqual(hostSM.getSession(hostSession.code).state, 'confirmed');

// Wrong tag must be rejected
const freshHost = new SessionManager();
const s2 = freshHost.createSession();
const g2 = new SessionManager().joinSession(s2.code, s2.publicKey);
freshHost.completeKeyExchange(s2.code, g2.session.publicKey);
assert.ok(!freshHost.confirmPeer(s2.code, 'a'.repeat(64)), 'bogus tag must be rejected');
console.log('✅ offline handshake OK\n');

// ============================================================================
console.log('Test 9: session code format + expiry + crypto self test');
assert.match(generateSessionCode(),
  /^[1-9A-HJ-NP-Za-km-z]{4}-[1-9A-HJ-NP-Za-km-z]{4}-[1-9A-HJ-NP-Za-km-z]{4}$/);

const smExp = new SessionManager();
const sExp = smExp.createSession();
smExp.sessions[sExp.code].expiresAt = Date.now() - 1000;
assert.strictEqual(smExp.getSession(sExp.code), null, 'expired session must return null');

assert.ok(verifyCrypto(), 'crypto self-test must pass');
console.log('✅ format/expiry/self-test OK\n');

// Cleanup test session file
const sessionsFile = path.join(process.env.COVALENT_HOME || path.join(os.homedir(), '.covalent'), 'sessions.json');
if (fs.existsSync(sessionsFile)) fs.unlinkSync(sessionsFile);

console.log('═══════════════════════════════════════════');
console.log('✅ crypto-session.test.js PASSED');
console.log('═══════════════════════════════════════════');
