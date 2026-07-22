import { test } from 'node:test';
import assert from 'node:assert/strict';

import { memoryStore } from '../../src/stores/memory.js';

function record(id, userId) {
  return {
    id,
    hash: 'x'.repeat(43),
    prefix: 'sk_live',
    userId,
    scopes: ['read'],
    createdAt: Date.now(),
  };
}

test('put + getById round-trip', async () => {
  const store = memoryStore();
  await store.put(record('id1', 'u1'));
  const r = await store.getById('id1');
  assert.equal(r.id, 'id1');
  assert.equal(r.userId, 'u1');
});

test('getById: unknown id → null', async () => {
  const store = memoryStore();
  assert.equal(await store.getById('missing'), null);
});

test('update: patches fields, returns updated record', async () => {
  const store = memoryStore();
  await store.put(record('id1', 'u1'));
  const updated = await store.update('id1', { name: 'Prod', lastUsedAt: 1234 });
  assert.equal(updated.name, 'Prod');
  assert.equal(updated.lastUsedAt, 1234);
});

test('update: moving userId reshuffles the reverse index', async () => {
  const store = memoryStore();
  await store.put(record('id1', 'u1'));
  await store.update('id1', { userId: 'u2' });
  assert.deepEqual(
    (await store.listByUser('u1')).map(r => r.id),
    [],
  );
  assert.deepEqual(
    (await store.listByUser('u2')).map(r => r.id),
    ['id1'],
  );
});

test('revoke: flips revokedAt on the stored record', async () => {
  const store = memoryStore();
  await store.put(record('id1', 'u1'));
  assert.equal(await store.revoke('id1', 'why'), true);
  const r = await store.getById('id1');
  assert.ok(r.revokedAt > 0);
  assert.equal(r.revokedReason, 'why');
  // Second revoke is a no-op.
  assert.equal(await store.revoke('id1'), false);
});

test('revokeAllForUser: returns count of newly-revoked rows', async () => {
  const store = memoryStore();
  await store.put(record('a', 'u'));
  await store.put(record('b', 'u'));
  await store.put(record('c', 'u2'));
  const n = await store.revokeAllForUser('u');
  assert.equal(n, 2);
});

test('listByUser: returns every record for the user', async () => {
  const store = memoryStore();
  await store.put(record('a', 'u'));
  await store.put(record('b', 'u'));
  const rows = await store.listByUser('u');
  const ids = rows.map(r => r.id).sort();
  assert.deepEqual(ids, ['a', 'b']);
});
