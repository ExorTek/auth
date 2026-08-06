import { describe, test, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import { createMemoryIncrStore, createRedisIncrStore } from '../src/incr-store.js';

describe('createMemoryIncrStore', () => {
  let store;
  afterEach(() => store?._stop());

  test('first incr returns count 1', async () => {
    store = createMemoryIncrStore();
    const res = await store.incr('k1', 10_000);
    assert.equal(res.count, 1);
    assert.ok(res.expiresAt > Date.now() - 100);
  });

  test('second incr returns count 2', async () => {
    store = createMemoryIncrStore();
    await store.incr('k1', 10_000);
    const res = await store.incr('k1', 10_000);
    assert.equal(res.count, 2);
  });

  test('expired entry resets to count 1', async () => {
    store = createMemoryIncrStore({ sweepMs: 60_000 });
    await store.incr('k1', 1);
    await new Promise(r => setTimeout(r, 10));
    const res = await store.incr('k1', 10_000);
    assert.equal(res.count, 1);
  });

  test('maxKeys evicts oldest entry', async () => {
    store = createMemoryIncrStore({ maxKeys: 2 });
    await store.incr('a', 60_000);
    await store.incr('b', 60_000);
    await store.incr('c', 60_000);
    assert.equal(store._size(), 2);
    // 'a' was evicted — fresh incr gives count 1
    const res = await store.incr('a', 60_000);
    assert.equal(res.count, 1);
  });

  test('LRU: accessing an entry refreshes its position', async () => {
    store = createMemoryIncrStore({ maxKeys: 2 });
    await store.incr('a', 60_000);
    await store.incr('b', 60_000);
    // touch 'a' again so 'b' becomes oldest
    await store.incr('a', 60_000);
    await store.incr('c', 60_000);
    // 'b' was evicted, 'a' survives
    const resA = await store.incr('a', 60_000);
    assert.equal(resA.count, 3);
    const resB = await store.incr('b', 60_000);
    assert.equal(resB.count, 1);
  });

  test('validation rejects bad maxKeys', () => {
    assert.throws(() => createMemoryIncrStore({ maxKeys: 0 }), /maxKeys/);
    assert.throws(() => createMemoryIncrStore({ maxKeys: -1 }), /maxKeys/);
    assert.throws(() => createMemoryIncrStore({ maxKeys: 1.5 }), /maxKeys/);
  });

  test('validation rejects bad sweepMs', () => {
    assert.throws(() => createMemoryIncrStore({ sweepMs: 500 }), /sweepMs/);
  });

  test('custom wrap callback is used for validation errors', () => {
    const wrap = msg => {
      throw new RangeError(`CUSTOM: ${msg}`);
    };
    assert.throws(() => createMemoryIncrStore({ maxKeys: 0 }, wrap), /CUSTOM:/);
  });

  test('_size tracks entries', async () => {
    store = createMemoryIncrStore();
    assert.equal(store._size(), 0);
    await store.incr('k1', 60_000);
    assert.equal(store._size(), 1);
  });
});

describe('createRedisIncrStore', () => {
  test('rejects a client without eval', () => {
    assert.throws(() => createRedisIncrStore({ get: () => {} }), /eval/);
  });

  test('incr passes node-redis its options form and returns the parsed result', async () => {
    let capturedArgs;
    // No ioredis surface, so the store treats it as node-redis.
    const fakeClient = {
      eval: async (...args) => {
        capturedArgs = args;
        return [1, 5000];
      },
    };
    const store = createRedisIncrStore(fakeClient, { keyPrefix: 'test:' });
    const res = await store.incr('mykey', 10_000);

    assert.equal(res.count, 1);
    assert.ok(res.expiresAt > Date.now() - 100);
    assert.deepEqual(capturedArgs[1], { keys: ['test:mykey'], arguments: ['10000'] });
  });

  test('incr passes ioredis its positional form', async () => {
    let capturedArgs;
    const fakeClient = {
      // `status` is part of ioredis's surface and selects the positional form.
      status: 'ready',
      eval: async (...args) => {
        capturedArgs = args;
        return [1, 5000];
      },
    };
    const store = createRedisIncrStore(fakeClient, { keyPrefix: 'test:' });
    await store.incr('mykey', 10_000);

    assert.equal(capturedArgs[1], 1, 'numKeys');
    assert.equal(capturedArgs[2], 'test:mykey');
    assert.equal(capturedArgs[3], '10000');
  });

  test("a driver failure surfaces through the caller's wrap, not as a raw reply", async () => {
    class FakeReply extends Error {}
    const fakeClient = {
      eval: async () => {
        throw new FakeReply('ERR something went wrong');
      },
    };
    const store = createRedisIncrStore(fakeClient, {}, msg => {
      throw new RangeError(`WRAPPED: ${msg}`);
    });

    await assert.rejects(() => store.incr('k', 1000), /WRAPPED: incr-store.incr: EVAL failed/);
  });

  test('handles Upstash string responses', async () => {
    const fakeClient = {
      eval: async () => ['3', '4500'],
    };
    const store = createRedisIncrStore(fakeClient);
    const res = await store.incr('k', 5000);
    assert.equal(res.count, 3);
  });

  test('handles scalar (non-array) response', async () => {
    const fakeClient = {
      eval: async () => 1,
    };
    const store = createRedisIncrStore(fakeClient);
    const res = await store.incr('k', 5000);
    assert.equal(res.count, 1);
  });

  test('default keyPrefix is empty string', async () => {
    let capturedKeys;
    const fakeClient = {
      eval: async (_script, options) => {
        capturedKeys = options.keys;
        return [1, 5000];
      },
    };
    const store = createRedisIncrStore(fakeClient);
    await store.incr('raw', 1000);
    assert.deepEqual(capturedKeys, ['raw']);
  });

  test('custom wrap callback for client validation', () => {
    const wrap = msg => {
      throw new RangeError(`CUSTOM: ${msg}`);
    };
    assert.throws(() => createRedisIncrStore({}, {}, wrap), /CUSTOM:/);
  });
});
