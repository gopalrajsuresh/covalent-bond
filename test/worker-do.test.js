/**
 * Unit tests for the Cloudflare Worker's SessionDO, run against a fake
 * Durable Object storage that ENFORCES the platform's real 128 KiB
 * per-value cap. This is the regression guard for the storage layout: a
 * max-size file transfer (~200 KB of hex ciphertext) must never be stored
 * in a value that Durable Objects would reject.
 *
 * Also covers: per-message chunked storage round-trip, queue-cap pruning
 * with oldestSeq reporting, the poll response byte budget, poll TTL
 * refresh, create/join field validation, and the disconnect membership gate.
 */

import assert from 'assert';
import { SessionDO } from '../cloudflare-worker/worker.js';

console.log('🧪 Running SessionDO storage tests...\n');

// Durable Object storage: 128 KiB per value, enforced on the stored bytes.
const DO_VALUE_LIMIT = 128 * 1024;

function fakeState() {
  const store = new Map();
  const sizeOf = (value) => JSON.stringify(value).length;
  return {
    store,
    storage: {
      async get(key) {
        if (Array.isArray(key)) {
          const out = new Map();
          for (const k of key) if (store.has(k)) out.set(k, store.get(k));
          return out;
        }
        return store.get(key);
      },
      async put(key, value) {
        const entries = typeof key === 'object' ? Object.entries(key) : [[key, value]];
        for (const [k, v] of entries) {
          assert.ok(sizeOf(v) <= DO_VALUE_LIMIT,
            `storage value for "${k}" exceeds the 128 KiB Durable Object cap (${sizeOf(v)} bytes)`);
        }
        for (const [k, v] of entries) store.set(k, v);
      },
      async delete(keys) {
        for (const k of Array.isArray(keys) ? keys : [keys]) store.delete(k);
      },
      async deleteAll() { store.clear(); },
      async setAlarm() {}
    }
  };
}

const hex64 = (c) => c.repeat(64);
const RID = hex64('a');
const HOST = hex64('1');
const GUEST = hex64('2');

async function pair() {
  const state = fakeState();
  const doObj = new SessionDO(state);
  const created = await doObj.handleCreate({ routingId: RID, publicKey: hex64('b'), peerId: HOST });
  assert.strictEqual(created.status, 200, 'create must succeed');
  const joined = await doObj.handleJoin({ publicKey: hex64('c'), peerId: GUEST });
  assert.strictEqual(joined.status, 200, 'join must succeed');
  return { state, doObj };
}

async function pollFor(doObj, peerId, since = 0) {
  const params = new URLSearchParams({ peerId, since: String(since) });
  const res = await doObj.handlePoll(params);
  assert.strictEqual(res.status, 200);
  return res.json();
}

// ============================================================================
console.log('Test 1: create/join validate peerId and publicKey');
{
  const doObj = new SessionDO(fakeState());
  const noPeer = await doObj.handleCreate({ routingId: RID, publicKey: hex64('b') });
  assert.strictEqual(noPeer.status, 400, 'create without peerId must be rejected');
  const junkKey = await doObj.handleCreate({ routingId: RID, publicKey: 'junk', peerId: HOST });
  assert.strictEqual(junkKey.status, 400, 'create with a non-hex publicKey must be rejected');

  await doObj.handleCreate({ routingId: RID, publicKey: hex64('b'), peerId: HOST });
  const badJoin = await doObj.handleJoin({ publicKey: 'x'.repeat(9000), peerId: GUEST });
  assert.strictEqual(badJoin.status, 400, 'join with junk publicKey must be rejected');
}
console.log('✅ field validation OK\n');

// ============================================================================
console.log('Test 2: a max-size transfer round-trips (the 128 KiB regression)');
{
  const { doObj } = await pair();
  // A 100 KB file becomes ~200+ KB of hex AES-GCM ciphertext inside the
  // encrypted payload. Storing this under a single value throws in real
  // Durable Objects; the fake storage enforces the same cap.
  const bigPayload = { v: 1, iv: 'ab'.repeat(12), encrypted: 'ff'.repeat(105 * 1024), authTag: 'cd'.repeat(16) };
  const sent = await doObj.handleSend({ fromPeerId: HOST, encryptedPayload: bigPayload });
  assert.strictEqual(sent.status, 200, 'a max-size send must not fail on the storage value cap');

  const { messages } = await pollFor(doObj, GUEST);
  const delivered = messages.find(m => m.from === HOST);
  assert.ok(delivered, 'the large message must be delivered');
  assert.strictEqual(delivered.payload.encrypted, bigPayload.encrypted, 'ciphertext must round-trip byte-identical');
}
console.log('✅ large transfer round-trips under the value cap\n');

// ============================================================================
console.log('Test 3: queue cap prunes oldest and reports oldestSeq');
{
  const { doObj } = await pair();
  for (let i = 0; i < 120; i++) {
    doObj.sendLog.clear(); // bypass the send throttle: this tests the queue, not the throttle
    const res = await doObj.handleSend({ fromPeerId: HOST, encryptedPayload: { n: i } });
    assert.strictEqual(res.status, 200);
  }
  // seq 1 was the system peer_joined message; 120 sends follow → nextSeq 122.
  const data = await pollFor(doObj, GUEST);
  assert.strictEqual(data.oldestSeq, 122 - 100, 'oldestSeq must reflect pruning');
  assert.ok(data.messages.length <= 100, 'never more than MAX_MESSAGES retained');
  assert.strictEqual(data.messages[0].seq, data.oldestSeq, 'delivery starts at the oldest retained seq');
  // Pruned message keys must actually be gone from storage
  const gone = await doObj.state.storage.get(doObj.msgKey(1));
  assert.strictEqual(gone, undefined, 'pruned message keys must be deleted');
}
console.log('✅ queue cap + oldestSeq OK\n');

// ============================================================================
console.log('Test 4: poll response respects the byte budget and resumes by seq');
{
  const { doObj } = await pair();
  const big = () => ({ encrypted: 'ee'.repeat(400 * 1024) }); // ~800 KB each
  for (let i = 0; i < 3; i++) {
    doObj.sendLog.clear();
    assert.strictEqual((await doObj.handleSend({ fromPeerId: HOST, encryptedPayload: big() })).status, 200);
  }
  const first = await pollFor(doObj, GUEST);
  assert.ok(first.messages.length >= 1, 'at least one message per poll');
  assert.ok(first.messages.length < 3, 'budget must split delivery across polls');
  const lastSeq = Math.max(...first.messages.map(m => m.seq));
  const second = await pollFor(doObj, GUEST, lastSeq);
  assert.ok(second.messages.length >= 1, 'the next poll must resume where the budget stopped');
  const total = first.messages.length + second.messages.length +
    (await pollFor(doObj, GUEST, Math.max(...second.messages.map(m => m.seq)))).messages.length;
  assert.ok(total >= 3, 'every message must eventually be delivered');
}
console.log('✅ poll budget OK\n');

// ============================================================================
console.log('Test 5: polling refreshes the session TTL');
{
  const { doObj } = await pair();
  doObj.session.expiresAt = Date.now() + 60 * 1000; // quiet session, nearly expired
  const before = doObj.session.expiresAt;
  await pollFor(doObj, GUEST);
  assert.ok(doObj.session.expiresAt > before, 'a poll from a connected peer must extend the session');
}
console.log('✅ poll TTL refresh OK\n');

// ============================================================================
console.log('Test 6: disconnect of the last peer wipes all storage');
{
  const { state, doObj } = await pair();
  doObj.sendLog.clear();
  await doObj.handleSend({ fromPeerId: HOST, encryptedPayload: { hello: 1 } });
  await doObj.handleDisconnect({ peerId: HOST });
  await doObj.handleDisconnect({ peerId: GUEST });
  assert.strictEqual(state.store.size, 0, 'no session or message keys may survive the last disconnect');
}
console.log('✅ storage wiped on last disconnect\n');

// ============================================================================
console.log('Test 7: disconnect from a non-member is ignored (no spoof, no queue flood)');
{
  const { doObj } = await pair();
  const stranger = hex64('9');
  for (let i = 0; i < 5; i++) {
    const res = await doObj.handleDisconnect({ peerId: stranger });
    assert.strictEqual(res.status, 200, 'stranger disconnect must not error (no probing signal)');
  }
  assert.strictEqual(doObj.session.peers.length, 2, 'membership must be untouched');
  const { messages } = await pollFor(doObj, GUEST);
  const spoofed = messages.filter(m => m.from === 'system' && m.payload.type === 'disconnect');
  assert.strictEqual(spoofed.length, 0, 'a non-member must not be able to enqueue disconnect messages');
}
console.log('✅ non-member disconnect ignored\n');

// ============================================================================
console.log('Test 8: disconnect on an expired session wipes storage without enqueueing');
{
  const { state, doObj } = await pair();
  doObj.session.expiresAt = Date.now() - 1000;
  const res = await doObj.handleDisconnect({ peerId: HOST });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(state.store.size, 0, 'an expired session must be wiped on disconnect');
}
console.log('✅ expired-session disconnect wipes storage\n');

console.log('═══════════════════════════════════════════');
console.log('✅ worker-do.test.js PASSED');
console.log('═══════════════════════════════════════════');
