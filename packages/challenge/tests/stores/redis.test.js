import { test } from 'node:test';
import assert from 'node:assert/strict';

import { redisStore } from '../../src/stores/redis.js';
import { ChallengeError, ErrorCode } from '../../src/index.js';

// A minimal in-memory fake that mimics ioredis's `eval` contract: runs the
// Lua-shape return `{ count, pttl }` for the INCR script. We don't parse Lua
// — we just simulate its semantics against a Map. That gives us end-to-end
// coverage of redisStore's client-boundary code without a live Redis.
function fakeClient() {
  const map = new Map();
  return {
    async eval(_script, _numKeys, key, ttlStr) {
      const ttl = Number(ttlStr);
      const now = Date.now();
      const existing = map.get(key);
      if (!existing || existing.expiresAt <= now) {
        map.set(key, { count: 1, expiresAt: now + ttl });
        return [1, ttl];
      }
      existing.count += 1;
      const pttl = Math.max(1, existing.expiresAt - now);
      return [existing.count, pttl];
    },
    _size: () => map.size,
  };
}

test('rejects a client that lacks eval', () => {
  assert.throws(
    () => redisStore({}),
    err => err instanceof ChallengeError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('incr: round-trips against a Lua-shaped fake client', async () => {
  const store = redisStore(fakeClient());
  const a = await store.incr('k', 60_000);
  const b = await store.incr('k', 60_000);
  assert.equal(a.count, 1);
  assert.equal(b.count, 2);
});

test('incr: coerces string return values (Upstash HTTP driver shape)', async () => {
  const client = {
    async eval() {
      return ['3', '12345'];
    },
  };
  const store = redisStore(client);
  const r = await store.incr('k', 60_000);
  assert.equal(r.count, 3);
  assert.ok(r.expiresAt > Date.now());
});

test('incr: falls back to ttlMs when pttl is missing / non-positive', async () => {
  const client = {
    async eval() {
      return [1, -1];
    },
  };
  const store = redisStore(client);
  const before = Date.now();
  const r = await store.incr('k', 60_000);
  assert.equal(r.count, 1);
  assert.ok(r.expiresAt >= before + 60_000 - 100);
});

test('keyPrefix: prepended before every call', async () => {
  let seenKey;
  const client = {
    async eval(_s, _n, key) {
      seenKey = key;
      return [1, 1000];
    },
  };
  const store = redisStore(client, { keyPrefix: 'myapp:chall:' });
  await store.incr('abc', 1000);
  assert.equal(seenKey, 'myapp:chall:abc');
});
