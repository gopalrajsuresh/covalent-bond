#!/usr/bin/env node
/**
 * Two-machine test driver: GUEST side.
 *
 * Prompts for the session code (shared out-of-band by the host), joins,
 * derives the session key, sends key confirmation, and exchanges an
 * encrypted message in each direction.
 *
 * Usage: node two-machine/guest.js [SESSION-CODE]
 *        (or pass the code interactively)
 * Relay: COVALENT_RELAY_URL env var (defaults to http://localhost:8787).
 */

import readline from 'readline';
import { SessionManager } from '../daemon/session-manager.js';
import { RelayClient } from '../relay/client.js';
import { PollingManager } from '../relay/poll.js';
import { generateKeypair, deriveRoutingId } from '../daemon/crypto.js';

const RELAY_URL = process.env.COVALENT_RELAY_URL
  || 'http://localhost:8787';

console.log('🔗 Covalent Bond Guest');
console.log(`Relay: ${RELAY_URL}\n`);

async function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => { rl.close(); resolve(answer.trim()); }));
}

const sessionCode = process.argv[2] || await prompt('📋 Enter the session code from the host: ');

const sm = new RelayClient(RELAY_URL);
const sessionManager = new SessionManager();

if (!(await sm.healthCheck())) {
  console.error('❌ Relay health check failed. Is the relay reachable?');
  process.exit(1);
}

const keypair = generateKeypair();
let joinResult;
try {
  joinResult = await sm.joinSession(deriveRoutingId(sessionCode), keypair.publicKey.toString('hex'));
} catch (error) {
  console.error(`❌ Failed to join: ${error.message}`);
  console.error('   - Make sure the host created the session first.');
  console.error('   - Check the code is exact (case-sensitive).');
  process.exit(1);
}

const { confirmationTag } = sessionManager.joinSession(sessionCode, joinResult.hostPublicKey, keypair);
console.log('✅ Joined and derived session key.\n');

const polling = new PollingManager(sm, sessionManager, {
  onConfirmed: () => {
    console.log('🔐 Secure channel established; host verified.\n');
  },
  onConfirmFailed: (reason) => {
    console.error(`🚨 Handshake failed: ${reason}`);
    console.error('   This is exactly what a key-substituting relay (MITM) would cause.');
    process.exit(1);
  },
  onChat: async (packet) => {
    console.log(`💬 Host says: "${packet.content}"`);
    await polling.sendEncrypted({ type: 'chat', content: 'Hello from the Guest!' });
    console.log('📤 Sent encrypted reply to host.');
    console.log('\n✅ TWO-MACHINE E2E TEST SUCCESSFUL (guest side).');
    // Linger briefly so the host's poll cycle can collect the reply before
    // we disconnect and the relay tears the session down.
    console.log('   (staying connected a few seconds so the host receives the reply...)');
    setTimeout(() => cleanup(0), 8000);
  }
});

polling.start();

// Prove knowledge of the session key to the host
await polling.sendKeyConfirmation(confirmationTag);
console.log('⏳ Sent key confirmation, waiting for host...\n');

const timeout = setTimeout(() => {
  console.error('⚠️  Timed out waiting for the host.');
  cleanup(1);
}, 120000);

async function cleanup(code) {
  clearTimeout(timeout);
  polling.stop();
  try { await sm.disconnect(); } catch { /* ignore */ }
  sessionManager.clearSession();
  process.exit(code);
}

process.on('SIGINT', () => cleanup(0));
