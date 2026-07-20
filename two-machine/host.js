#!/usr/bin/env node
/**
 * Two-machine test driver: HOST side.
 *
 * Creates a session, prints the code to share out-of-band, waits for the
 * guest, completes the authenticated handshake, then exchanges an
 * encrypted message in each direction.
 *
 * Usage: node two-machine/host.js
 * Relay: COVALENT_RELAY_URL env var (defaults to http://localhost:8787).
 */

import { SessionManager } from '../daemon/session-manager.js';
import { RelayClient } from '../relay/client.js';
import { PollingManager } from '../relay/poll.js';

const RELAY_URL = process.env.COVALENT_RELAY_URL
  || 'http://localhost:8787';

const sm = new RelayClient(RELAY_URL);
const sessionManager = new SessionManager();

console.log('🔗 Covalent Bond Host');
console.log(`Relay: ${RELAY_URL}\n`);

if (!(await sm.healthCheck())) {
  console.error('❌ Relay health check failed. Is the relay reachable?');
  process.exit(1);
}

const session = sessionManager.createSession();
await sm.createSession(session.routingId, session.publicKey);

console.log('✅ Session created.');
console.log('───────────────────────────────────────');
console.log('📢 SHARE THIS CODE WITH THE OTHER MACHINE (out-of-band):');
console.log(`      ${session.code}`);
console.log('───────────────────────────────────────');
console.log('(The relay never sees this code; it is the shared secret.)\n');
console.log('⏳ Waiting for peer to join and confirm...\n');

let confirmed = false;

const polling = new PollingManager(sm, sessionManager, {
  onConfirmed: async () => {
    confirmed = true;
    console.log('🔐 Secure channel established; peer verified the session code.\n');
    await polling.sendEncrypted({ type: 'chat', content: 'Hello from the Host!' });
    console.log('📤 Sent encrypted greeting to guest.\n');
  },
  onConfirmFailed: (reason) => {
    console.error(`🚨 Handshake failed: ${reason}`);
    process.exit(1);
  },
  onChat: (packet) => {
    console.log(`💬 Guest says: "${packet.content}"`);
    console.log('\n✅ TWO-MACHINE E2E TEST SUCCESSFUL (host side).');
    cleanup(0);
  }
});

polling.start();

// Default 2 minutes; a live cross-machine test with a human on the other
// end can set COVALENT_HOST_TIMEOUT_MS higher (the session code itself
// expires after 30 idle minutes regardless).
const parsedTimeout = parseInt(process.env.COVALENT_HOST_TIMEOUT_MS || '', 10);
const TIMEOUT_MS = Number.isFinite(parsedTimeout) && parsedTimeout > 0 ? parsedTimeout : 120000;
const timeout = setTimeout(() => {
  console.error('⚠️  Timed out waiting for the guest.');
  cleanup(1);
}, TIMEOUT_MS);

async function cleanup(code) {
  clearTimeout(timeout);
  polling.stop();
  try { await sm.disconnect(); } catch { /* ignore */ }
  sessionManager.clearSession();
  process.exit(code);
}

process.on('SIGINT', () => cleanup(0));
