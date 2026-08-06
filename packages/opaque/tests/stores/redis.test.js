import { test } from 'node:test';
import assert from 'node:assert/strict';

import { redisStore } from '../../src/stores/redis.js';
import { OpaqueError, ErrorCode } from '../../src/index.js';

/**
 * Minimal in-memory fake of ioredis's contract. Covers just what
 * opaque's redisStore actually calls: get / set (plain and with 'PX'
 * TTL) / del. TTL is simulated with a plain expiresAt timestamp —
 * good enough for the JS-boundary logic this suite targets; real
 * expiry semantics are covered by redis.integration.test.js.
 */
function fakeClient() {
  const kv = new Map();
  return {
    kv,
    // `status` is part of ioredis's surface and is how the store recognises
    // the positional argument convention this fake implements.
    status: 'ready',
    async get(k) {
      const entry = kv.get(k);
      if (!entry) return null;
      if (entry.expiresAt !== null && entry.expiresAt <= Date.now()) {
        kv.delete(k);
        return null;
      }
      return entry.value;
    },
    async set(k, v, ...rest) {
      const px = rest[0] === 'PX' ? Number(rest[1]) : null;
      kv.set(k, { value: v, expiresAt: px !== null ? Date.now() + px : null });
    },
    async del(k) {
      return kv.delete(k) ? 1 : 0;
    },
  };
}

/**
 * Mimics node-redis's object-options `set` signature. It exposes none of
 * ioredis's surface, so the store detects it as node-redis and passes the
 * options form. It throws on a positional call to make a regression loud —
 * the real client would accept it and silently drop the TTL.
 */
function fakeNodeRedisV4Client() {
  const kv = new Map();
  return {
    kv,
    async get(k) {
      const entry = kv.get(k);
      return entry ? entry.value : null;
    },
    async set(k, v, opts) {
      if (typeof opts === 'string') {
        throw new TypeError('this client does not support the ioredis SET signature');
      }
      const px = opts?.PX ? Number(opts.PX) : null;
      kv.set(k, { value: v, expiresAt: px !== null ? Date.now() + px : null });
    },
    async del(k) {
      return kv.delete(k) ? 1 : 0;
    },
  };
}

test('rejects a client that lacks get/set/del', () => {
  assert.throws(
    () => redisStore({}),
    err => err instanceof OpaqueError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('set + get round-trip (no TTL)', async () => {
  const store = redisStore(fakeClient());
  await store.set('hash1', { userId: 'usr_1' });
  assert.deepEqual(await store.get('hash1'), { userId: 'usr_1' });
});

test('set + get round-trip with expiresIn', async () => {
  const client = fakeClient();
  const store = redisStore(client);
  await store.set('hash1', { a: 1 }, { expiresIn: '1h' });
  const entry = client.kv.get('opaque:hash1');
  assert.ok(entry.expiresAt > Date.now());
});

test('get returns null for an unknown key', async () => {
  const store = redisStore(fakeClient());
  assert.equal(await store.get('nope'), null);
});

test('delete returns true/false based on whether the key existed', async () => {
  const store = redisStore(fakeClient());
  await store.set('hash1', { a: 1 });
  assert.equal(await store.delete('hash1'), true);
  assert.equal(await store.delete('hash1'), false);
});

test('keyPrefix option is prepended before every call', async () => {
  const client = fakeClient();
  const store = redisStore(client, { keyPrefix: 'myapp:opaque:' });
  await store.set('hash1', { a: 1 });
  assert.ok(client.kv.has('myapp:opaque:hash1'));
});

test('falls back to object-options set() (node-redis v4 shape)', async () => {
  const store = redisStore(fakeNodeRedisV4Client());
  await store.set('hash1', { a: 1 }, { expiresIn: '1h' });
  assert.deepEqual(await store.get('hash1'), { a: 1 });
});
