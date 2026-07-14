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
  assert.deepEqual(
    list.map(r => r.sid),
    ['new', 'old'],
  );
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

test('eviction prefers expired garbage, then anonymous, over authenticated sessions', async () => {
  const store = memoryStore({ maxSessions: 3, sweepMs: 60_000 });
  const now = Date.now();
  // Oldest = authenticated; middle = expired; newest = anonymous.
  await store.put(makeRecord({ sid: 'auth', uid: 'u1', lastSeenAt: now - 3000 }));
  await store.put(makeRecord({ sid: 'dead', uid: 'u2', lastSeenAt: now - 2000, expiresAt: now - 1 }));
  await store.put(makeRecord({ sid: 'anon', uid: null, isAnonymous: true, lastSeenAt: now - 1000 }));

  // 4th put: expired 'dead' should be swept — both live sessions survive.
  await store.put(makeRecord({ sid: 'new1', uid: 'u3' }));
  assert.equal(await store.get('dead'), null);
  assert.ok(await store.get('auth'));
  assert.ok(await store.get('anon'));

  // 5th put: no garbage left — the anonymous session goes, NOT the
  // older authenticated one.
  await store.put(makeRecord({ sid: 'new2', uid: 'u4' }));
  assert.equal(await store.get('anon'), null);
  assert.ok(await store.get('auth'));
  store._stop();
});

test('update(lastSeenAt) refreshes LRU position', async () => {
  const store = memoryStore({ maxSessions: 2, sweepMs: 60_000 });
  const now = Date.now();
  await store.put(makeRecord({ sid: 'a', uid: null, isAnonymous: true, lastSeenAt: now - 2000 }));
  await store.put(makeRecord({ sid: 'b', uid: null, isAnonymous: true, lastSeenAt: now - 1000 }));
  // Touch 'a' — it becomes most-recently-seen, so 'b' is now the victim.
  await store.update('a', { lastSeenAt: now });
  await store.put(makeRecord({ sid: 'c', uid: null, isAnonymous: true }));
  assert.ok(await store.get('a'));
  assert.equal(await store.get('b'), null);
  store._stop();
});
