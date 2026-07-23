import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { createMemoryRecordStore, createRedisRecordStore } from '../src/record-store.js';

// Memory

describe('createMemoryRecordStore', () => {
  test('put + getById round-trip with shallow copy', async () => {
    const store = createMemoryRecordStore({ idField: 'id', indexField: 'userId' });
    const rec = { id: 'k1', userId: 'u1', name: 'Test' };
    await store.put(rec);
    const got = await store.getById('k1');
    assert.deepEqual(got, rec);
    // shallow copy — mutation doesn't leak
    got.name = 'Changed';
    assert.equal((await store.getById('k1')).name, 'Test');
  });

  test('put + getById with deep copy', async () => {
    const store = createMemoryRecordStore({ idField: 'id', indexField: 'email', copyStrategy: 'deep' });
    const rec = { id: 'k1', email: 'a@b.com', meta: { x: 1 } };
    await store.put(rec);
    // mutate the original — should not affect stored copy
    rec.meta.x = 99;
    assert.equal((await store.getById('k1')).meta.x, 1);
  });

  test('put stores shallow copy — caller mutation does not leak', async () => {
    const store = createMemoryRecordStore({ idField: 'id', indexField: 'userId', copyStrategy: 'shallow' });
    const rec = { id: 'k1', userId: 'u1', name: 'Original' };
    await store.put(rec);
    rec.name = 'Mutated';
    assert.equal((await store.getById('k1')).name, 'Original');
  });

  test('getById: unknown id → null', async () => {
    const store = createMemoryRecordStore({ idField: 'id', indexField: 'userId' });
    assert.equal(await store.getById('nope'), null);
  });

  test('update: merges patch and returns updated record', async () => {
    const store = createMemoryRecordStore({ idField: 'id', indexField: 'userId' });
    await store.put({ id: 'k1', userId: 'u1', name: 'Old' });
    const updated = await store.update('k1', { name: 'New' });
    assert.equal(updated.name, 'New');
    assert.equal((await store.getById('k1')).name, 'New');
  });

  test('update: unknown id → null', async () => {
    const store = createMemoryRecordStore({ idField: 'id', indexField: 'userId' });
    assert.equal(await store.update('nope', { name: 'x' }), null);
  });

  test('update: re-indexes when indexField changes', async () => {
    const store = createMemoryRecordStore({ idField: 'id', indexField: 'userId' });
    await store.put({ id: 'k1', userId: 'u1' });
    await store.update('k1', { userId: 'u2' });
    assert.deepEqual(await store.listByIndex('u1'), []);
    assert.equal((await store.listByIndex('u2')).length, 1);
  });

  test('listByIndex: returns all records for the index value', async () => {
    const store = createMemoryRecordStore({ idField: 'id', indexField: 'userId' });
    await store.put({ id: 'k1', userId: 'u1' });
    await store.put({ id: 'k2', userId: 'u1' });
    await store.put({ id: 'k3', userId: 'u2' });
    const list = await store.listByIndex('u1');
    assert.equal(list.length, 2);
    assert.deepEqual(list.map(r => r.id).sort(), ['k1', 'k2']);
  });

  test('listByIndex: unknown index → empty array', async () => {
    const store = createMemoryRecordStore({ idField: 'id', indexField: 'userId' });
    assert.deepEqual(await store.listByIndex('nobody'), []);
  });

  test('byId and byIndex are exposed for domain-specific methods', async () => {
    const store = createMemoryRecordStore({ idField: 'id', indexField: 'userId' });
    await store.put({ id: 'k1', userId: 'u1' });
    assert.ok(store.byId instanceof Map);
    assert.ok(store.byIndex instanceof Map);
    assert.ok(store.byId.has('k1'));
    assert.ok(store.byIndex.get('u1').has('k1'));
  });

  test('_size tracks entries', async () => {
    const store = createMemoryRecordStore({ idField: 'id', indexField: 'userId' });
    assert.equal(store._size(), 0);
    await store.put({ id: 'k1', userId: 'u1' });
    assert.equal(store._size(), 1);
  });

  test('works with sid as idField', async () => {
    const store = createMemoryRecordStore({ idField: 'sid', indexField: 'uid' });
    await store.put({ sid: 's1', uid: 'u1' });
    const got = await store.getById('s1');
    assert.equal(got.sid, 's1');
  });
});

// Redis

function createFakeRedisClient() {
  const data = new Map();
  const sets = new Map();
  return {
    async get(key) {
      return data.get(key) ?? null;
    },
    async set(key, value) {
      data.set(key, value);
    },
    async del(key) {
      data.delete(key);
    },
    async sadd(key, member) {
      if (!sets.has(key)) sets.set(key, new Set());
      sets.get(key).add(member);
    },
    async srem(key, member) {
      const s = sets.get(key);
      if (s) s.delete(member);
    },
    async smembers(key) {
      return [...(sets.get(key) ?? [])];
    },
    async mget(...keys) {
      return keys.map(k => data.get(k) ?? null);
    },
    _data: data,
    _sets: sets,
  };
}

describe('createRedisRecordStore', () => {
  test('put + getById without tombstones', async () => {
    const client = createFakeRedisClient();
    const store = createRedisRecordStore(client, {
      idField: 'id',
      indexField: 'userId',
      keyPrefix: 'ak:',
    });
    await store.put({ id: 'k1', userId: 'u1', name: 'Test' });
    const got = await store.getById('k1');
    assert.equal(got.name, 'Test');
    // verify index
    assert.deepEqual(await client.smembers('ak:u:u1'), ['k1']);
  });

  test('put + getById with tombstones', async () => {
    const client = createFakeRedisClient();
    const store = createRedisRecordStore(client, {
      idField: 'id',
      indexField: 'userId',
      keyPrefix: 'ak:',
      tombstones: true,
      applyTombstone(record, tomb) {
        record.revokedAt = tomb.at;
        return record;
      },
    });
    await store.put({ id: 'k1', userId: 'u1' });
    // no tombstone → clean record
    let got = await store.getById('k1');
    assert.equal(got.revokedAt, undefined);
    // write tombstone
    await store.writeTombstone('k1', { at: 123 });
    got = await store.getById('k1');
    assert.equal(got.revokedAt, 123);
  });

  test('update: merges patch', async () => {
    const client = createFakeRedisClient();
    const store = createRedisRecordStore(client, {
      idField: 'id',
      indexField: 'userId',
      keyPrefix: 'p:',
    });
    await store.put({ id: 'k1', userId: 'u1', name: 'Old' });
    const updated = await store.update('k1', { name: 'New' });
    assert.equal(updated.name, 'New');
  });

  test('update: re-indexes when indexField changes', async () => {
    const client = createFakeRedisClient();
    const store = createRedisRecordStore(client, {
      idField: 'id',
      indexField: 'userId',
      keyPrefix: 'p:',
    });
    await store.put({ id: 'k1', userId: 'u1' });
    await store.update('k1', { userId: 'u2' });
    assert.deepEqual(await client.smembers('p:u:u1'), []);
    assert.deepEqual(await client.smembers('p:u:u2'), ['k1']);
  });

  test('listByIndex: returns records and prunes dead index entries', async () => {
    const client = createFakeRedisClient();
    const store = createRedisRecordStore(client, {
      idField: 'id',
      indexField: 'userId',
      keyPrefix: 'p:',
    });
    await store.put({ id: 'k1', userId: 'u1' });
    await store.put({ id: 'k2', userId: 'u1' });
    // delete k2's record directly to simulate expiry
    await client.del('p:k2');
    const list = await store.listByIndex('u1');
    assert.equal(list.length, 1);
    assert.equal(list[0].id, 'k1');
    // k2 pruned from index
    assert.deepEqual((await client.smembers('p:u:u1')).sort(), ['k1']);
  });

  test('fetchIndexRecords: returns id-record pairs', async () => {
    const client = createFakeRedisClient();
    const store = createRedisRecordStore(client, {
      idField: 'id',
      indexField: 'userId',
      keyPrefix: 'p:',
    });
    await store.put({ id: 'k1', userId: 'u1' });
    const pairs = await store.fetchIndexRecords('u1');
    assert.equal(pairs.length, 1);
    assert.equal(pairs[0][0], 'k1');
    assert.equal(pairs[0][1].id, 'k1');
  });

  test('custom indexPrefix and tombstonePrefix', async () => {
    const client = createFakeRedisClient();
    const store = createRedisRecordStore(client, {
      idField: 'id',
      indexField: 'email',
      keyPrefix: 'ml:',
      indexPrefix: 'e:',
      tombstonePrefix: 't:',
      tombstones: true,
      applyTombstone(rec) {
        rec.dead = true;
        return rec;
      },
    });
    await store.put({ id: 'k1', email: 'a@b.com' });
    assert.deepEqual(await client.smembers('ml:e:a@b.com'), ['k1']);
    await store.writeTombstone('k1', { at: 1 });
    assert.ok(client._data.has('ml:t:k1'));
  });
});
