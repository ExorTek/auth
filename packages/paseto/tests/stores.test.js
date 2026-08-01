/**
 * Store adapters — memory backend + Redis mock clients (dialect
 * detection, basic ops, markUsed CAS). A live-Redis run lives in
 * token-pair.redis.integration.test.js.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createStore, createMemoryStore } from '../src/stores.js';
import { PasetoError, ErrorCode } from '../src/index.js';

const NOW = () => Math.floor(Date.now() / 1000);

// memory

test('memory: add/get/has/delete round-trip with expiry enforcement', async () => {
  const store = createMemoryStore();
  await store.add('k', NOW() + 60, { familyId: 'F1' });
  assert.equal(await store.has('k'), true);
  assert.equal((await store.get('k')).metadata.familyId, 'F1');
  await store.delete('k');
  assert.equal(await store.has('k'), false);
  store._stop();
});

test('memory: expired records are never returned', async () => {
  const store = createMemoryStore({ gc: { strategy: 'lazy' } });
  await store.add('k', NOW() - 1);
  assert.equal(await store.get('k'), null);
  store._stop();
});

test('memory: deleteAll removes a whole family', async () => {
  const store = createMemoryStore();
  await store.add('a', NOW() + 60, { familyId: 'F' });
  await store.add('b', NOW() + 60, { familyId: 'F' });
  await store.add('c', NOW() + 60, { familyId: 'G' });
  assert.equal(await store.deleteAll({ familyId: 'F' }), 2);
  assert.equal(await store.has('c'), true);
  store._stop();
});

test('memory: markUsed stamps usedAt once (CAS semantics)', async () => {
  const store = createMemoryStore();
  await store.add('r', NOW() + 60, { familyId: 'F', usedAt: null });
  const first = await store.markUsed('r', 1000);
  assert.equal(first.swapped, true);
  const second = await store.markUsed('r', 2000);
  assert.equal(second.swapped, false);
  assert.equal(second.record.metadata.usedAt, 1000);
  store._stop();
});

// redis — mock clients

test('redis: ioredis-style client uses positional EX', async () => {
  const setCalls = [];
  const client = {
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
  await store.add('key1', NOW() + 60, { familyId: 'F1' });
  assert.equal(setCalls[0].key, 'test:key1');
  assert.equal(setCalls[0].rest[0], 'EX');
  assert.equal((await store.get('key1')).metadata.familyId, 'F1');
});

test('redis: node-redis-style client uses options-object EX', async () => {
  const setCalls = [];
  class NodeRedisClient {
    async set(key, value, opts) {
      setCalls.push({ key, value, opts });
    }
    async get() {
      return null;
    }
    async del() {}
  }
  const store = createStore('redis', { client: new NodeRedisClient(), keyPrefix: 'test:' });
  await store.add('k2', NOW() + 60);
  assert.equal(setCalls[0].opts.EX > 0, true);
});

test('redis: markUsed dispatches the right EVAL form per dialect', async () => {
  // ioredis — positional args
  const io = {
    async eval(script, numkeys, key, arg) {
      this.call = { numkeys, key, arg };
      return [1, JSON.stringify({ expiresAt: 1, metadata: { usedAt: Number(arg) } })];
    },
  };
  Object.defineProperty(io.constructor, 'name', { value: 'Redis' });
  const ioStore = createStore('redis', { client: io, keyPrefix: 't:' });
  const ioRes = await ioStore.markUsed('k', 42);
  assert.deepEqual(io.call, { numkeys: 1, key: 't:k', arg: '42' });
  assert.equal(ioRes.swapped, true);

  // node-redis — options object { keys, arguments }
  class NodeRedisClient {
    async eval(script, opts) {
      this.call = opts;
      return [0, JSON.stringify({ expiresAt: 1, metadata: { usedAt: 7 } })];
    }
  }
  const nr = new NodeRedisClient();
  const nrStore = createStore('redis', { client: nr, keyPrefix: 't:' });
  const nrRes = await nrStore.markUsed('k', 42);
  assert.deepEqual(nr.call, { keys: ['t:k'], arguments: ['42'] });
  assert.equal(nrRes.swapped, false);
});

test('redis: missing client raises STORE_ERROR', () => {
  assert.throws(
    () => createStore('redis', /** @type {any} */ ({})),
    err => err instanceof PasetoError && err.code === ErrorCode.STORE_ERROR,
  );
});

test('createStore: custom requires an impl object; unknown kind rejected', () => {
  const impl = { add() {}, get() {}, delete() {}, deleteAll() {}, has() {} };
  assert.equal(createStore('custom', { impl }), impl);
  assert.throws(
    () => createStore('custom', {}),
    err => err.code === ErrorCode.INVALID_ARGUMENT,
  );
  assert.throws(
    () => createStore('nope'),
    err => err.code === ErrorCode.INVALID_ARGUMENT,
  );
});
