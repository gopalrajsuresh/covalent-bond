#!/usr/bin/env node

/**
 * Covalent Bond CLI Entry Point
 * Starts the MCP server (stdio)
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { CovalentBondServer } from '../mcp/server.js';

// Optional .env next to this install (covalent-bond/.env). Real environment
// variables always win; this only fills in values that aren't already set.
// Hand-rolled on purpose: no dotenv dependency.
function loadDotEnv() {
  const envPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '.env');
  let text;
  try {
    text = fs.readFileSync(envPath, 'utf8');
  } catch {
    return; // no .env, fine
  }
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!m || line.trimStart().startsWith('#')) continue;
    const value = m[2].replace(/^["']|["']$/g, '');
    if (!(m[1] in process.env)) process.env[m[1]] = value;
  }
}
loadDotEnv();

// Relay endpoint. Set COVALENT_RELAY_URL to your deployed Cloudflare Worker,
// or run the local mock relay (`npm run relay:dev`) and point at :8787.
const RELAY_URL = process.env.COVALENT_RELAY_URL || 'http://localhost:8787';

/**
 * Print startup banner
 */
function printBanner() {
  console.error('═══════════════════════════════════════════');
  console.error('🔗 Covalent Bond - P2P Agent Collaboration');
  console.error('═══════════════════════════════════════════');
  console.error('');
}

/**
 * Print usage instructions
 */
function printUsage() {
  console.error('Usage:');
  console.error('  npx covalent-bond          Start MCP server');
  console.error('');
  console.error('Available MCP Tools:');
  console.error('  bond_connect           Create new session');
  console.error('  bond_join              Join existing session');
  console.error('  bond_send              Send file to peer');
  console.error('  bond_accept            Accept pending transfer');
  console.error('  bond_decline           Decline pending transfer');
  console.error('  bond_message           Send encrypted chat message');
  console.error('  bond_wait              Wait for the next peer event');
  console.error('  bond_status            Show connection status');
  console.error('  bond_end               Disconnect from session');
  console.error('');
}

/**
 * Start MCP server
 */
async function startMCPServer() {
  try {
    printBanner();

    console.error('Starting MCP server...');
    console.error(`Relay URL: ${RELAY_URL}`);
    console.error('');
    console.error('═══════════════════════════════════════════');
    console.error('✅ Covalent Bond MCP Server Ready');
    console.error('═══════════════════════════════════════════');
    console.error('');
    console.error('To connect with another agent:');
    console.error('  1. Call bond_connect to create a session');
    console.error('  2. Share the session code with the other agent');
    console.error('  3. Other agent calls bond_join with the code');
    console.error('');
    console.error('Listening for MCP requests on stdio...');
    console.error('');

    // Create and start MCP server
    const server = new CovalentBondServer(RELAY_URL);
    await server.run();

  } catch (error) {
    console.error('');
    console.error('═══════════════════════════════════════════');
    console.error('❌ Error Starting Covalent Bond');
    console.error('═══════════════════════════════════════════');
    console.error('');
    console.error(error.message);
    console.error('');

    if (error.code === 'ECONNREFUSED') {
      console.error('Relay server is not reachable.');
      console.error(`Check that ${RELAY_URL} is running.`);
      console.error('');
      console.error('For local testing, start the mock relay:');
      console.error('  npm run relay:dev        # http://localhost:8787');
      console.error('Then set COVALENT_RELAY_URL=http://localhost:8787');
      console.error('');
    }

    process.exit(1);
  }
}

/**
 * Main entry point
 */
async function main() {
  const args = process.argv.slice(2);

  // Show usage if --help or -h
  if (args.includes('--help') || args.includes('-h')) {
    printBanner();
    printUsage();
    process.exit(0);
  }

  // Default action: start MCP server
  await startMCPServer();
}

main().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
