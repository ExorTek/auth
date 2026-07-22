import { test } from 'node:test';
import assert from 'node:assert/strict';

import { redisStore } from '../../src/stores/redis.js';
import { ApiKeyError, ErrorCode } from '../../src/index.js';

/**
 * Minimal in-memory fake of ioredis's contract. Covers just what the
 * apikey redisStore actually calls: get / set / del / sadd / srem /
 * smembers / mget. Uses lowercase method names — the node-redis v4
 * camelCase fallback branch is exercised by {@link fakeCamelClient}.
 */
function fakeClient() {
  const kv = new Map();
  const sets = new Map();
  return {
    kv,
    sets,
    async get(k) {
      return kv.has(k) ? kv.get(k) : null;
    },
    async set(k, v) {
      kv.set(k, v);
    },
    async del(k) {
      kv.delete(k);
    },
    async sadd(k, v) {
      let s = sets.get(k);
      if (!s) {
        s = new Set();
        sets.set(k, s);
      }
      s.add(v);
    },
    async srem(k, v) {
      const s = sets.get(k);
      if (s) s.delete(v);
    },
    async smembers(k) {
      const s = sets.get(k);
      return s ? [...s] : [];
    },
    async mget(...keys) {
      return keys.map(k => (kv.has(k) ? kv.get(k) : null));
    },
  };
}

/**
 * Same behaviour, camelCase methods (mimics node-redis v4). Exercises
 * the sAdd / sRem / sMembers / mGet fallback branches in redisStore.
 */
function fakeCamelClient() {
  const c = fakeClient();
  return {
    ...c,
    sadd: undefined,
    srem: undefined,
    smembers: undefined,
    mget: undefined,
    sAdd: c.sadd,
    sRem: c.srem,
    sMembers: c.smembers,
    mGet: async keys => c.mget(...keys),
  };
}

function newRecord(id, userId, extras = {}) {
  return {
    id,
    hash: 'x'.repeat(43),
    prefix: 'sk_live',
    userId,
    scopes: ['read'],
    createdAt: Date.now(),
    ...extras,
  };
}

test('rejects a client that lacks the required methods', () => {
  assert.throws(
    () => redisStore({}),
    err => err instanceof ApiKeyError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('put + getById round-trip against a fake ioredis client', async () => {
  const client = fakeClient();
  const store = redisStore(client);
  await store.put(newRecord('id1', 'u1'));
  const back = await store.getById('id1');
  assert.equal(back.id, 'id1');
  assert.equal(back.userId, 'u1');
});

test('getById: unknown → null', async () => {
  const store = redisStore(fakeClient());
  assert.equal(await store.getById('missing'), null);
});

test('getById: JSON parse errors → null', async () => {
  const client = fakeClient();
  await client.set('apikey:corrupt', '{not-json');
  const store = redisStore(client);
  assert.equal(await store.getById('corrupt'), null);
});

test('update: patches fields, returns updated record', async () => {
  const store = redisStore(fakeClient());
  await store.put(newRecord('id1', 'u1'));
  const updated = await store.update('id1', { name: 'Prod', lastUsedAt: 12345 });
  assert.equal(updated.name, 'Prod');
  assert.equal(updated.lastUsedAt, 12345);
});

test('update: userId change reshuffles the reverse index', async () => {
  const client = fakeClient();
  const store = redisStore(client);
  await store.put(newRecord('id1', 'u1'));
  await store.update('id1', { userId: 'u2' });
  assert.deepEqual([...(client.sets.get('apikey:u:u1') ?? new Set())], []);
  assert.deepEqual([...(client.sets.get('apikey:u:u2') ?? new Set())], ['id1']);
});

test('revoke: flips revokedAt; second call is a no-op', async () => {
  const store = redisStore(fakeClient());
  await store.put(newRecord('id1', 'u1'));
  assert.equal(await store.revoke('id1', 'why'), true);
  const after = await store.getById('id1');
  assert.ok(after.revokedAt > 0);
  assert.equal(after.revokedReason, 'why');
  assert.equal(await store.revoke('id1'), false);
});

test('revokeAllForUser: revokes every non-revoked record for the user', async () => {
  const store = redisStore(fakeClient());
  await store.put(newRecord('a', 'u'));
  await store.put(newRecord('b', 'u'));
  await store.put(newRecord('c', 'u2'));
  const n = await store.revokeAllForUser('u');
  assert.equal(n, 2);
});

test('listByUser: returns every record for the user', async () => {
  const store = redisStore(fakeClient());
  await store.put(newRecord('a', 'u'));
  await store.put(newRecord('b', 'u'));
  const rows = await store.listByUser('u');
  const ids = rows.map(r => r.id).sort();
  assert.deepEqual(ids, ['a', 'b']);
});

test('listByUser: prunes dead-index references', async () => {
  const client = fakeClient();
  const store = redisStore(client);
  await store.put(newRecord('alive', 'u'));
  // Force a dead reference: the set has "ghost" but no record blob.
  await client.sadd('apikey:u:u', 'ghost');
  const rows = await store.listByUser('u');
  const ids = rows.map(r => r.id).sort();
  assert.deepEqual(ids, ['alive']);
  // Dead reference should be pruned from the set now.
  const set = [...(client.sets.get('apikey:u:u') ?? [])].sort();
  assert.deepEqual(set, ['alive']);
});

test('camelCase fallback: works with node-redis v4 style sAdd / sMembers / mGet', async () => {
  const store = redisStore(fakeCamelClient());
  await store.put(newRecord('id1', 'u1'));
  const back = await store.getById('id1');
  assert.equal(back.id, 'id1');
  const rows = await store.listByUser('u1');
  assert.equal(rows.length, 1);
});

test('keyPrefix override: prepended everywhere', async () => {
  const client = fakeClient();
  const store = redisStore(client, { keyPrefix: 'myapp:apikey:' });
  await store.put(newRecord('id1', 'u1'));
  assert.ok(client.kv.has('myapp:apikey:id1'));
  assert.ok(client.sets.has('myapp:apikey:u:u1'));
});

test('revoke: unknown id → false, without touching the store', async () => {
  const store = redisStore(fakeClient());
  assert.equal(await store.revoke('missing'), false);
});
