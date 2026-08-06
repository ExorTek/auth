import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryRegistryStore, createRedisRegistryStore } from '../src/registry-store.js';

// A minimal typed error stand-in for the package error classes.
class StoreError extends Error {
  constructor(code, message, extra) {
    super(message, extra);
    this.code = code;
  }
}
const CODE = 'STORE_ERROR';
const binding = {
  StoreError,
  storeErrorCode: CODE,
  parseIntervalSeconds: () => 300,
};

const future = () => Math.floor(Date.now() / 1000) + 60;

test('memory: add / has / get / delete roundtrip', async () => {
  const store = createMemoryRegistryStore(binding, { gc: { strategy: 'lazy' } });
  await store.add('a', future(), { fam: 'x' });
  assert.equal(await store.has('a'), true);
  assert.equal((await store.get('a')).metadata.fam, 'x');
  await store.delete('a');
  assert.equal(await store.has('a'), false);
  assert.equal(await store.get('a'), null);
});

test('memory: expiry is enforced on read', async () => {
  const store = createMemoryRegistryStore(binding, { gc: { strategy: 'lazy' } });
  await store.add('past', Math.floor(Date.now() / 1000) - 1);
  assert.equal(await store.has('past'), false);
  assert.equal(store.size(), 0); // evicted on read
});

test('memory: deleteAll matches on metadata', async () => {
  const store = createMemoryRegistryStore(binding, { gc: { strategy: 'lazy' } });
  await store.add('a', future(), { fam: 'x' });
  await store.add('b', future(), { fam: 'x' });
  await store.add('c', future(), { fam: 'y' });
  assert.equal(await store.deleteAll({ fam: 'x' }), 2);
  assert.equal(store.size(), 1);
});

test('memory: markUsed stamps usedAt once (CAS)', async () => {
  const store = createMemoryRegistryStore(binding, { gc: { strategy: 'lazy' } });
  await store.add('r', future());
  const first = await store.markUsed('r', 111);
  assert.equal(first.swapped, true);
  assert.equal(first.record.metadata.usedAt, 111);
  const second = await store.markUsed('r', 222);
  assert.equal(second.swapped, false);
  assert.equal(second.record.metadata.usedAt, 111);
});

test('memory: lru evicts oldest past the cap', async () => {
  const store = createMemoryRegistryStore(binding, { gc: { strategy: 'lru', maxSize: 2 } });
  await store.add('a', future());
  await store.add('b', future());
  await store.add('c', future());
  assert.equal(store.size(), 2);
  assert.equal(await store.has('a'), false); // oldest dropped
});

test('memory: invalid input throws the bound StoreError', async () => {
  const store = createMemoryRegistryStore(binding, { gc: { strategy: 'lazy' } });
  await assert.rejects(
    () => store.add('', future()),
    err => err instanceof StoreError && err.code === CODE,
  );
  await assert.rejects(
    () => store.add('k', NaN),
    err => err instanceof StoreError,
  );
});

// A fake node-redis-style client: options-object calling convention.
function fakeNodeRedis() {
  const map = new Map();
  return {
    store: map,
    async set(key, value) {
      map.set(key, value);
    },
    async get(key) {
      return map.has(key) ? map.get(key) : null;
    },
    async del(key) {
      map.delete(key);
    },
    async exists(key) {
      return map.has(key) ? 1 : 0;
    },
  };
}

const redisBinding = { StoreError, storeErrorCode: CODE, defaultKeyPrefix: 'test:' };

test('redis: requires a client', () => {
  assert.throws(
    () => createRedisRegistryStore(redisBinding, /** @type {any} */ ({})),
    err => err instanceof StoreError && err.code === CODE,
  );
});

test('redis: add / has / get / delete via node-redis dialect', async () => {
  const client = fakeNodeRedis();
  const store = createRedisRegistryStore(redisBinding, { client, dialect: 'node-redis' });
  await store.add('a', future(), { fam: 'x' });
  assert.ok(client.store.has('test:a'));
  assert.equal(await store.has('a'), true);
  assert.equal((await store.get('a')).metadata.fam, 'x');
  await store.delete('a');
  assert.equal(await store.has('a'), false);
});

test('redis: size() is unsupported', () => {
  const store = createRedisRegistryStore(redisBinding, { client: fakeNodeRedis(), dialect: 'node-redis' });
  assert.throws(
    () => store.size(),
    err => err instanceof StoreError && err.code === CODE,
  );
});
