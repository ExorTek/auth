import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createStore } from '../src/stores.js';
import { JwtError, ErrorCode } from '../src/index.js';

const NOW = () => Math.floor(Date.now() / 1000);

// memory store — basic ops
test('memory: add / has / get / delete roundtrip', async () => {
  const store = createStore('memory');
  await store.add('a', NOW() + 60, { userId: 'u1' });
  assert.equal(await store.has('a'), true);
  const record = await store.get('a');
  assert.ok(record);
  assert.equal(record.metadata.userId, 'u1');
  await store.delete('a');
  assert.equal(await store.has('a'), false);
  store._stop();
});

test('memory: expired entry returns false under lazy strategy', async () => {
  const store = createStore('memory', { gc: { strategy: 'lazy' } });
  await store.add('a', NOW() - 1); // already expired
  assert.equal(await store.has('a'), false);
  assert.equal(await store.get('a'), null);
  store._stop();
});

test('memory: expired entry returns false under interval strategy (before next sweep)', async () => {
  const store = createStore('memory', { gc: { strategy: 'interval', interval: '1h' } });
  await store.add('a', NOW() - 1);
  assert.equal(await store.has('a'), false);
  assert.equal(await store.get('a'), null);
  store._stop();
});

test('memory: expired entry returns false under lru strategy (before next sweep)', async () => {
  const store = createStore('memory', { gc: { strategy: 'lru', interval: '1h', maxSize: 100 } });
  await store.add('a', NOW() - 1);
  assert.equal(await store.has('a'), false);
  assert.equal(await store.get('a'), null);
  store._stop();
});

test('memory: deleteAll matches on metadata filter', async () => {
  const store = createStore('memory');
  await store.add('r1', NOW() + 60, { family: 'F1', userId: 'u1' });
  await store.add('r2', NOW() + 60, { family: 'F1', userId: 'u1' });
  await store.add('r3', NOW() + 60, { family: 'F2', userId: 'u2' });
  const count = await store.deleteAll({ family: 'F1' });
  assert.equal(count, 2);
  assert.equal(await store.has('r1'), false);
  assert.equal(await store.has('r2'), false);
  assert.equal(await store.has('r3'), true);
  store._stop();
});

test('memory: LRU eviction caps size', async () => {
  const store = createStore('memory', { gc: { strategy: 'lru', maxSize: 2 } });
  await store.add('a', NOW() + 60);
  await store.add('b', NOW() + 60);
  await store.add('c', NOW() + 60);
  // 'a' should have been evicted (oldest insertion).
  assert.equal(await store.has('a'), false);
  assert.equal(await store.has('b'), true);
  assert.equal(await store.has('c'), true);
  store._stop();
});

test('memory: invalid inputs raise STORE_ERROR', async () => {
  const store = createStore('memory');
  await assert.rejects(
    () => store.add('', NOW() + 60),
    err => err instanceof JwtError && err.code === ErrorCode.STORE_ERROR,
  );
  await assert.rejects(
    () => store.add('a', NaN),
    err => err instanceof JwtError && err.code === ErrorCode.STORE_ERROR,
  );
  store._stop();
});

// custom store — user-supplied impl
test("custom: caller's implementation is used verbatim", async () => {
  const map = new Map();
  const impl = {
    async add(key, expiresAt, metadata) {
      map.set(key, { expiresAt, metadata });
    },
    async has(key) {
      return map.has(key);
    },
    async get(key) {
      return map.get(key) || null;
    },
    async delete(key) {
      map.delete(key);
    },
    async deleteAll() {
      const n = map.size;
      map.clear();
      return n;
    },
    size() {
      return map.size;
    },
    _stop() {},
  };
  const store = createStore('custom', { impl });
  await store.add('a', NOW() + 60, { any: 'meta' });
  assert.equal(await store.has('a'), true);
  assert.equal((await store.get('a')).metadata.any, 'meta');
  await store.delete('a');
  assert.equal(await store.has('a'), false);
});

test('custom: missing impl raises INVALID_ARGUMENT', () => {
  assert.throws(
    () => createStore('custom', /** @type {any} */ ({})),
    err => err instanceof JwtError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('createStore: unknown kind raises INVALID_ARGUMENT', () => {
  assert.throws(
    () => createStore(/** @type {any} */ ('mongodb'), {}),
    err => err instanceof JwtError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

// redis store — mock client (dialect detection + basic ops)
test('redis: ioredis-style client — positional EX', async () => {
  const setCalls = [];
  const client = {
    // ioredis class name is 'Redis' — mock via constructor property
    async set(key, value, ...rest) {
      setCalls.push({ key, value, rest });
    },
    async exists(key) {
      return setCalls.some(c => c.key === key) ? 1 : 0;
    },
    async get(key) {
      const c = setCalls.find(x => x.key === key);
      return c ? c.value : null;
    },
    async del() {},
    async scan() {
      return ['0', []];
    },
  };
  Object.defineProperty(client.constructor, 'name', { value: 'Redis' });

  const store = createStore('redis', { client, keyPrefix: 'test:' });
  await store.add('key1', NOW() + 60, { family: 'F1' });
  assert.equal(setCalls[0].key, 'test:key1');
  assert.equal(setCalls[0].rest[0], 'EX'); // ioredis positional
  const record = await store.get('key1');
  assert.ok(record);
  assert.equal(record.metadata.family, 'F1');
});

test('redis: node-redis-style client — options object EX', async () => {
  const setCalls = [];
  class NodeRedisClient {
    async set(key, value, opts) {
      setCalls.push({ key, value, opts });
    }
    async exists(key) {
      return setCalls.some(c => c.key === key) ? 1 : 0;
    }
    async get(key) {
      const c = setCalls.find(x => x.key === key);
      return c ? c.value : null;
    }
    async del() {}
    async scan() {
      return { cursor: 0, keys: [] };
    }
  }
  const client = new NodeRedisClient();

  const store = createStore('redis', { client, keyPrefix: 'test:' });
  await store.add('k2', NOW() + 60);
  assert.equal(setCalls[0].opts.EX > 0, true);
});

test('redis: missing client raises STORE_ERROR', () => {
  assert.throws(
    () => createStore('redis', /** @type {any} */ ({})),
    err => err instanceof JwtError && err.code === ErrorCode.STORE_ERROR,
  );
});
