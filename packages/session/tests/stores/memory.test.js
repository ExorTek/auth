import { test } from 'node:test';
import assert from 'node:assert/strict';
import { memoryStore } from '../../src/stores/memory.js';

function makeRecord(overrides = {}) {
  const now = Date.now();
  return {
    sid: overrides.sid ?? `sid-${Math.random().toString(36).slice(2, 8)}`,
    uid: overrides.uid ?? 'u1',
    claims: overrides.claims ?? {},
    issuedAt: now,
    expiresAt: overrides.expiresAt ?? now + 60_000,
    lastSeenAt: overrides.lastSeenAt ?? now,
    isAnonymous: overrides.uid === null,
    revoked: false,
    ...overrides,
  };
}

test('put + get round trip', async () => {
  const store = memoryStore();
  const rec = makeRecord({ sid: 'a1' });
  await store.put(rec);
  assert.deepEqual(await store.get('a1'), rec);
  store._stop();
});

test('get: missing sid returns null', async () => {
  const store = memoryStore();
  assert.equal(await store.get('missing'), null);
  store._stop();
});

test('update: merge-patches an existing record', async () => {
  const store = memoryStore();
  await store.put(makeRecord({ sid: 'x', claims: { role: 'user' } }));
  const updated = await store.update('x', { claims: { role: 'admin' } });
  assert.equal(updated.claims.role, 'admin');
  assert.equal((await store.get('x')).claims.role, 'admin');
  store._stop();
});

test('update: returns null for missing sid', async () => {
  const store = memoryStore();
  assert.equal(await store.update('missing', { claims: {} }), null);
  store._stop();
});

test('revoke: marks and persists reason', async () => {
  const store = memoryStore();
  await store.put(makeRecord({ sid: 'v', uid: 'u1' }));
  assert.equal(await store.revoke('v', 'logout'), true);
  const rec = await store.get('v');
  assert.equal(rec.revoked, true);
  assert.equal(rec.revokedReason, 'logout');
  store._stop();
});

test('revoke: missing sid returns false', async () => {
  const store = memoryStore();
  assert.equal(await store.revoke('missing'), false);
  store._stop();
});

test('revokeAllForUser: kills every session for user', async () => {
  const store = memoryStore();
  await store.put(makeRecord({ sid: 'a', uid: 'u1' }));
  await store.put(makeRecord({ sid: 'b', uid: 'u1' }));
  await store.put(makeRecord({ sid: 'c', uid: 'u2' }));
  assert.equal(await store.revokeAllForUser('u1', 'compromise'), 2);
  assert.equal((await store.get('a')).revoked, true);
  assert.equal((await store.get('b')).revoked, true);
  assert.equal((await store.get('c')).revoked, false);
  store._stop();
});

test('revokeAllExcept: keeps the named sid', async () => {
  const store = memoryStore();
  await store.put(makeRecord({ sid: 'a', uid: 'u1' }));
  await store.put(makeRecord({ sid: 'b', uid: 'u1' }));
  await store.put(makeRecord({ sid: 'c', uid: 'u1' }));
  assert.equal(await store.revokeAllExcept('u1', 'b'), 2);
  assert.equal((await store.get('a')).revoked, true);
  assert.equal((await store.get('b')).revoked, false);
  assert.equal((await store.get('c')).revoked, true);
  store._stop();
});

test('listByUser: only active + newest first', async () => {
  const store = memoryStore();
  await store.put(makeRecord({ sid: 'old', uid: 'u1', lastSeenAt: 1000 }));
  await store.put(makeRecord({ sid: 'new', uid: 'u1', lastSeenAt: 5000 }));
  await store.put(makeRecord({ sid: 'expired', uid: 'u1', expiresAt: Date.now() - 1 }));
  const revoked = makeRecord({ sid: 'revoked', uid: 'u1' });
  await store.put(revoked);
  await store.revoke('revoked');
  const list = await store.listByUser('u1');
  assert.deepEqual(list.map(r => r.sid), ['new', 'old']);
  store._stop();
});

test('countActive: does not count revoked / expired', async () => {
  const store = memoryStore();
  await store.put(makeRecord({ sid: 'a', uid: 'u1' }));
  await store.put(makeRecord({ sid: 'b', uid: 'u1', expiresAt: Date.now() - 1 }));
  const r = makeRecord({ sid: 'c', uid: 'u1' });
  await store.put(r);
  await store.revoke('c');
  assert.equal(await store.countActive('u1'), 1);
  store._stop();
});

test('anonymous records skip the user index', async () => {
  const store = memoryStore();
  await store.put(makeRecord({ sid: 'g', uid: null }));
  assert.equal(await store.countActive('anything'), 0);
  const rec = await store.get('g');
  assert.equal(rec.uid, null);
  store._stop();
});

test('rejects bad maxSessions / sweepMs at construction', () => {
  assert.throws(() => memoryStore({ maxSessions: 0 }));
  assert.throws(() => memoryStore({ sweepMs: 100 }));
});

test('LRU eviction when maxSessions hit', async () => {
  const store = memoryStore({ maxSessions: 3 });
  await store.put(makeRecord({ sid: 'a', uid: 'u1', lastSeenAt: 1 }));
  await store.put(makeRecord({ sid: 'b', uid: 'u1', lastSeenAt: 2 }));
  await store.put(makeRecord({ sid: 'c', uid: 'u1', lastSeenAt: 3 }));
  await store.put(makeRecord({ sid: 'd', uid: 'u1', lastSeenAt: 4 }));
  assert.equal(await store.get('a'), null, 'oldest evicted');
  assert.ok(await store.get('d'));
  store._stop();
});
