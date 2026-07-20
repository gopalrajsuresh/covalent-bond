/**
 * MITM regression test.
 *
 * Simulates a MALICIOUS RELAY that substitutes public keys during the
 * exchange: the classic attack on unauthenticated Diffie-Hellman. The
 * attacker sees everything the relay sees (routing ID, public keys,
 * encrypted blobs) but does NOT know the session code, which is shared
 * out-of-band.
 *
 * * The protocol must guarantee:
 *  1. The attacker cannot derive either session key (code key is missing).
 *  2. Substituted-key traffic fails decryption / key confirmation.
 *  3. The PollingManager aborts the session on that failure.
 */

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import os from 'os';

import {
  generateKeypair,
  deriveSharedSecret,
  deriveCodeKey,
  deriveSessionKey,
  transcriptHash,
  keyConfirmationTag,
  encrypt,
  decrypt,
  generateNonce
} from '../daemon/crypto.js';
import { SessionManager } from '../daemon/session-manager.js';
import { PollingManager } from '../relay/poll.js';

console.log('🧪 Running MITM regression test...\n');

// --- Setup: honest host and guest, attacker in the middle ----------------
const hostSM = new SessionManager();
const hostSession = hostSM.createSession();
const code = hostSession.code; // attacker never learns this

// Attacker (the relay) substitutes its own keypairs in both directions
const attackerForGuest = generateKeypair(); // presented to the guest as "host key"
const attackerForHost = generateKeypair();  // presented to the host as "guest key"

// Guest joins, but receives the ATTACKER's public key instead of the host's
const guestSM = new SessionManager();
const { session: guestSession, confirmationTag: guestConfirm } =
  guestSM.joinSession(code, attackerForGuest.publicKey.toString('hex'));

// Host completes the exchange with the ATTACKER's public key
const { session: hostKeyed } =
  hostSM.completeKeyExchange(code, attackerForHost.publicKey.toString('hex'));

console.log('Test 1: attacker cannot derive either session key without the code');
// The attacker knows both DH shared secrets (it owns the substituted keys)...
const attackerSecretWithGuest = deriveSharedSecret(
  attackerForGuest.privateKey, Buffer.from(guestSession.publicKey, 'hex'));
const attackerSecretWithHost = deriveSharedSecret(
  attackerForHost.privateKey, Buffer.from(hostKeyed.publicKey, 'hex'));

// ...but without the session code it can only guess the code key.
const attackerGuessCodeKey = deriveCodeKey('AAAA-BBBB-CCCC'); // wrong guess
const attackerGuestKey = deriveSessionKey(
  attackerSecretWithGuest,
  attackerGuessCodeKey,
  transcriptHash(attackerForGuest.publicKey, Buffer.from(guestSession.publicKey, 'hex'))
);
assert.notStrictEqual(
  attackerGuestKey.toString('hex'),
  guestSession.sessionKey,
  'attacker without the code must not derive the guest session key'
);
// Real key requires the real code key: prove that WITH the code it would match,
// i.e., the code key is exactly the missing ingredient.
const withRealCode = deriveSessionKey(
  attackerSecretWithGuest,
  deriveCodeKey(code),
  transcriptHash(attackerForGuest.publicKey, Buffer.from(guestSession.publicKey, 'hex'))
);
assert.strictEqual(withRealCode.toString('hex'), guestSession.sessionKey,
  'sanity: the code key is the only missing ingredient for the attacker');
console.log('✅ attacker locked out without the session code\n');

console.log('Test 2: forwarded traffic fails decryption across the split keys');
// Host and guest now hold DIFFERENT session keys (different DH secrets AND
// different transcripts). Any blob forwarded by the attacker fails GCM auth.
assert.notStrictEqual(hostKeyed.sessionKey, guestSession.sessionKey);
const guestBlob = encrypt(JSON.stringify({ type: 'key_confirm', role: 'guest', tag: guestConfirm }),
  guestSession.sessionKey);
assert.throws(
  () => decrypt(guestBlob, hostKeyed.sessionKey),
  /.+/,
  'guest traffic must not decrypt under the host key'
);
console.log('✅ split keys cannot exchange any readable traffic\n');

console.log('Test 3: PollingManager aborts the session on the failed handshake');
let abortReason = null;
const fakeRelay = {
  getSession: () => ({ routingId: 'x' }),
  disconnect: async () => {},
  poll: async () => []
};
const hostPolling = new PollingManager(fakeRelay, hostSM, {
  onConfirmFailed: (reason) => { abortReason = reason; }
});

// Deliver the guest's (attacker-forwarded) key_confirm blob to the host
await hostPolling.handleMessage({
  from: 'guest-peer-id',
  payload: guestBlob,
  timestamp: Date.now()
});

assert.ok(abortReason, 'session must be aborted');
assert.match(abortReason, /decrypt/i);
assert.strictEqual(hostSM.getCurrentSession(), null, 'host session must be cleared');
console.log(`✅ session aborted: "${abortReason}"\n`);

console.log('Test 4: a forged confirmation tag is rejected even if decryption were possible');
// Suppose the attacker could somehow speak to the host under the host's key
// (it cannot; this is defense in depth): a tag computed without the real
// session key still fails verification.
const freshHostSM = new SessionManager();
const s = freshHostSM.createSession();
const g = new SessionManager().joinSession(s.code, s.publicKey);
freshHostSM.completeKeyExchange(s.code, g.session.publicKey);
const forgedTag = keyConfirmationTag(attackerGuestKey, 'guest',
  Buffer.from(g.session.transcript, 'hex'));
assert.ok(!freshHostSM.confirmPeer(s.code, forgedTag), 'forged tag must be rejected');
console.log('✅ forged confirmation rejected\n');

// Cleanup
guestSM.clearSession();
const sessionsFile = path.join(process.env.COVALENT_HOME || path.join(os.homedir(), '.covalent'), 'sessions.json');
if (fs.existsSync(sessionsFile)) fs.unlinkSync(sessionsFile);

console.log('═══════════════════════════════════════════');
console.log('✅ mitm.test.js PASSED - key-substituting relay is defeated');
console.log('═══════════════════════════════════════════');
