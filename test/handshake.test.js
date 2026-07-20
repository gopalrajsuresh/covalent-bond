/**
 * End-to-end handshake test through the (in-process) mock relay:
 * host create -> guest join -> mutual key confirmation -> encrypted
 * file transfer in both directions -> disconnect.
 *
 * This exercises the exact wiring the MCP server uses: RelayClient +
 * PollingManager + SessionManager + FileSender/FileReceiver.
 */

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import os from 'os';

import { startMockRelay, stopMockRelay, resetMockRelay } from './mock-relay-server.js';
import { SessionManager } from '../daemon/session-manager.js';
import { RelayClient } from '../relay/client.js';
import { PollingManager } from '../relay/poll.js';
import { FileSender } from '../transfer/sender.js';
import { FileReceiver } from '../transfer/receiver.js';
import { generateKeypair, deriveRoutingId } from '../daemon/crypto.js';

const PORT = 8791;
const RELAY_URL = `http://127.0.0.1:${PORT}`;

console.log('🧪 Running relay handshake test...\n');

await startMockRelay(PORT);
resetMockRelay();

// --- Host side ---------------------------------------------------------
const hostSM = new SessionManager();
const hostRelay = new RelayClient(RELAY_URL);
const hostEvents = { confirmed: false, failed: null, transfers: [] };
const hostReceiver = new FileReceiver();

const hostPolling = new PollingManager(hostRelay, hostSM, {
  onConfirmed: () => { hostEvents.confirmed = true; },
  onConfirmFailed: (reason) => { hostEvents.failed = reason; },
  onFileTransfer: (packet, from) => {
    hostEvents.transfers.push(hostReceiver.processIncomingTransfer(packet, from));
  }
});

const hostSession = hostSM.createSession();
await hostRelay.createSession(hostSession.routingId, hostSession.publicKey);
console.log(`✅ Host created session ${hostSession.code} (relay sees only ${hostSession.routingId.substring(0, 12)}...)`);

// --- Guest side --------------------------------------------------------
const guestSM = new SessionManager();
const guestRelay = new RelayClient(RELAY_URL);
const guestEvents = { confirmed: false, failed: null, transfers: [] };
const guestReceiver = new FileReceiver();

const guestPolling = new PollingManager(guestRelay, guestSM, {
  onConfirmed: () => { guestEvents.confirmed = true; },
  onConfirmFailed: (reason) => { guestEvents.failed = reason; },
  onFileTransfer: (packet, from) => {
    guestEvents.transfers.push(guestReceiver.processIncomingTransfer(packet, from));
  }
});

const guestKeypair = generateKeypair();
const joinResult = await guestRelay.joinSession(
  deriveRoutingId(hostSession.code),
  guestKeypair.publicKey.toString('hex')
);
const { confirmationTag: guestConfirm } = guestSM.joinSession(
  hostSession.code,
  joinResult.hostPublicKey,
  guestKeypair
);
console.log('✅ Guest joined and derived session key');

// Guest proves knowledge of the session key
await guestPolling.sendKeyConfirmation(guestConfirm);

// --- Handshake completion (deterministic manual polling) ----------------
await hostPolling.pollOnce();   // host: peer_joined -> completeKeyExchange, then guest confirm -> reply
assert.ok(hostEvents.confirmed, 'host must reach confirmed state');
assert.strictEqual(hostSM.getCurrentSession().state, 'confirmed');

await guestPolling.pollOnce();  // guest: host's key_confirm arrives
assert.ok(guestEvents.confirmed, 'guest must reach confirmed state');
assert.strictEqual(guestSM.getCurrentSession().state, 'confirmed');

assert.strictEqual(
  hostSM.getCurrentSession().sessionKey,
  guestSM.getCurrentSession().sessionKey,
  'both sides must hold the same session key'
);
console.log('✅ Mutual key confirmation complete - secure channel established');

// --- File transfer host -> guest ----------------------------------------
const tmpFile = path.join(os.tmpdir(), 'covalent-bond-test-payload.js');
fs.writeFileSync(tmpFile, 'export const answer = 42;\n');

const hostSender = new FileSender(hostRelay, hostSM);
const sendResult = await hostSender.sendFile(tmpFile, 'here is the module');
assert.ok(sendResult.success);

await guestPolling.pollOnce();
assert.strictEqual(guestEvents.transfers.length, 1, 'guest must receive the transfer');
const consent = guestEvents.transfers[0];
assert.ok(consent.requiresConsent, 'transfer must require consent');
assert.strictEqual(consent.preview.filename, 'covalent-bond-test-payload.js');

// Accept and verify content lands in the incoming dir
const accepted = await guestReceiver.acceptTransfer(consent.transferId);
assert.ok(accepted.content.includes('answer = 42'));
assert.ok(fs.existsSync(accepted.filepath), 'accepted file must exist on disk');
assert.ok(accepted.injectionText.includes('UNTRUSTED-PEER-CONTENT'),
  'peer content must be wrapped in untrusted markers');
fs.unlinkSync(accepted.filepath);
console.log('✅ File transfer host -> guest with consent flow OK');

// --- File transfer guest -> host (rate limit: separate session state) ---
const tmpFile2 = path.join(os.tmpdir(), 'covalent-bond-test-reply.md');
fs.writeFileSync(tmpFile2, '# Reply\nack\n');

const guestSender = new FileSender(guestRelay, guestSM);
await guestSender.sendFile(tmpFile2, 'ack');

await hostPolling.pollOnce();
assert.strictEqual(hostEvents.transfers.length, 1, 'host must receive the reply transfer');
console.log('✅ File transfer guest -> host OK');

// --- Unconfirmed sessions must not be able to send ----------------------
const strangerSM = new SessionManager();
const strangerSession = strangerSM.createSession();
const strangerSender = new FileSender(hostRelay, strangerSM);
await assert.rejects(
  () => strangerSender.sendFile(tmpFile, 'nope'),
  /not confirmed/i,
  'sending on an unconfirmed session must be rejected'
);
strangerSM.clearSession();
console.log('✅ Unconfirmed sessions cannot send');

// --- Cleanup -------------------------------------------------------------
hostPolling.stop();
guestPolling.stop();
await hostRelay.disconnect();
await guestRelay.disconnect();
fs.unlinkSync(tmpFile);
fs.unlinkSync(tmpFile2);
hostSM.clearSession();
guestSM.clearSession();
await stopMockRelay();

assert.strictEqual(hostEvents.failed, null, 'no handshake failure expected on host');
assert.strictEqual(guestEvents.failed, null, 'no handshake failure expected on guest');

console.log('\n═══════════════════════════════════════════');
console.log('✅ handshake.test.js PASSED');
console.log('═══════════════════════════════════════════');
