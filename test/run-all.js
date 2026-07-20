/**
 * Test runner: executes every *.test.js suite in this directory as a
 * separate process and reports a summary. Exit code is non-zero if any
 * suite fails.
 */

import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const testDir = path.dirname(fileURLToPath(import.meta.url));

// Isolate every suite's ~/.covalent (audit log, incoming files) into a temp
// directory so test runs never pollute the user's real audit trail.
const covalentHome = fs.mkdtempSync(path.join(os.tmpdir(), 'covalent-test-'));
process.env.COVALENT_HOME = covalentHome;

const suites = fs.readdirSync(testDir)
  .filter(f => f.endsWith('.test.js'))
  .sort();

console.log(`\n🧪 Covalent Bond test suite (${suites.length} files)\n`);

const results = [];

for (const suite of suites) {
  const started = process.hrtime.bigint();
  const proc = spawnSync(process.execPath, [path.join(testDir, suite)], {
    encoding: 'utf8'
  });
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  const passed = proc.status === 0;
  results.push({ suite, passed, ms });

  if (!passed) {
    console.log(`\n──────── ${suite} FAILED ────────`);
    process.stdout.write(proc.stdout || '');
    process.stderr.write(proc.stderr || '');
    console.log(`──────────────────────────────────\n`);
  } else {
    console.log(`✅ ${suite.padEnd(30)} ${ms.toFixed(0).padStart(6)} ms`);
  }
}

const failed = results.filter(r => !r.passed);

console.log('\n═══════════════════════════════════════════');
if (failed.length === 0) {
  console.log(`✅ ALL ${results.length} SUITES PASSED`);
  console.log('═══════════════════════════════════════════\n');
  fs.rmSync(covalentHome, { recursive: true, force: true });
  process.exit(0);
} else {
  console.log(`❌ ${failed.length}/${results.length} SUITES FAILED: ${failed.map(f => f.suite).join(', ')}`);
  console.log('═══════════════════════════════════════════\n');
  process.exit(1);
}
