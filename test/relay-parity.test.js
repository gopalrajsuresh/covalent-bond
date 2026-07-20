/**
 * Relay parity: the deployed Cloudflare Worker and the in-process mock relay
 * must agree on protocol constants. The mock imports them from
 * relay/constants.js; the Worker keeps its own copies because Cloudflare
 * cannot import outside the worker directory at deploy time. This test reads
 * worker.js as text and asserts every shared value matches, so the two
 * implementations can never silently drift.
 */

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  SESSION_TTL_MS, MAX_MESSAGES, MAX_PEERS,
  SEND_WINDOW_MS, SEND_MAX, PAYLOAD_LIMITS, POLL_MAX_BYTES, ERROR_CODES
} from '../relay/constants.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const worker = fs.readFileSync(path.join(here, '..', 'cloudflare-worker', 'worker.js'), 'utf8');

console.log('🧪 Running relay parity test...\n');

// Pull a `const NAME = <expr>;` out of the worker and evaluate the numeric expr.
function workerNumber(name) {
  const m = worker.match(new RegExp(`const\\s+${name}\\s*=\\s*([^;]+);`));
  assert.ok(m, `worker.js must define ${name}`);
  // Only simple arithmetic on number literals appears here.
  assert.ok(/^[\d_\s*+/()-]+$/.test(m[1]), `${name} expr not a plain number: ${m[1]}`);
  return Function(`"use strict";return (${m[1]})`)();
}

console.log('Test 1: session TTL, queue cap, peer cap');
assert.strictEqual(workerNumber('SESSION_TTL_MS'), SESSION_TTL_MS, 'SESSION_TTL_MS drift');
assert.strictEqual(workerNumber('MAX_MESSAGES'), MAX_MESSAGES, 'MAX_MESSAGES drift');
assert.strictEqual(workerNumber('MAX_PEERS'), MAX_PEERS, 'MAX_PEERS drift');
assert.strictEqual(workerNumber('POLL_MAX_BYTES'), POLL_MAX_BYTES, 'POLL_MAX_BYTES drift');
console.log('✅ core caps match\n');

console.log('Test 2: send throttle');
const sendLimit = worker.match(/const\s+SEND_LIMIT\s*=\s*\{([^}]+)\}/);
assert.ok(sendLimit, 'worker.js must define SEND_LIMIT');
assert.ok(sendLimit[1].includes(`windowMs: ${SEND_WINDOW_MS}`), 'SEND_LIMIT.windowMs drift');
assert.ok(sendLimit[1].includes(`maxRequests: ${SEND_MAX}`), 'SEND_LIMIT.maxRequests drift');
console.log('✅ send throttle matches\n');

console.log('Test 3: payload limits');
for (const [ep, bytes] of Object.entries(PAYLOAD_LIMITS)) {
  const m = worker.match(new RegExp(`'/${ep}':\\s*([^,\\n]+)`));
  assert.ok(m, `worker.js PAYLOAD_LIMITS must include /${ep}`);
  assert.strictEqual(Function(`"use strict";return (${m[1].trim()})`)(), bytes, `/${ep} payload cap drift`);
}
console.log('✅ payload limits match\n');

console.log('Test 4: error codes');
for (const [k, v] of Object.entries(ERROR_CODES)) {
  assert.ok(worker.includes(`${k}: '${v}'`), `worker.js missing/renamed error code ${k}`);
}
console.log('✅ error codes match\n');

console.log('═══════════════════════════════════════════');
console.log('✅ relay-parity.test.js PASSED');
console.log('═══════════════════════════════════════════');
