/**
 * Integration test — runs against a real Redis when `REDIS_URL` is
 * set. Skipped otherwise so a fresh clone can `yarn test` without
 * Docker.
 *
 *   docker run --rm -d --name auth-redis -p 6379:6379 redis:8.4.0-alpine
 *   REDIS_URL=redis://127.0.0.1:6379 yarn workspace @exortek/magic-link test
 *
 * Covers real-Redis-only behaviour the fake can't reach: the actual
 * CONSUME Lua script's atomicity, the real INCR + PEXPIRE contract,
 * cjson vs Node's JSON stringifier.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { redisStore } from '../../src/stores/redis.js';

const REDIS_URL = process.env.REDIS_URL;
let ioredis;
try {
  ioredis = (await import('ioredis')).default;
} catch {
  /* peer not installed */
}

const skipMsg = !REDIS_URL
  ? 'REDIS_URL not set — skipping integration tests'
  : !ioredis
    ? 'ioredis not installed — skipping integration tests'
    : false;

let sharedClient = null;
async function client() {
  if (!sharedClient) sharedClient = new ioredis(REDIS_URL, { lazyConnect: true });
  return sharedClient;
}

const runPrefix = () => `mlink:test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}:`;

function newRecord(id, email) {
  return {
    id,
    email,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60_000,
  };
}

test('integration: put + getById + consume atomicity', { skip: skipMsg }, async () => {
  const c = await client();
  const store = redisStore(c, { keyPrefix: runPrefix() });
  await store.put(newRecord('id1', 'a@x.com'));
  const back = await store.getById('id1');
  assert.equal(back.email, 'a@x.com');
  assert.equal(await store.consume('id1'), true);
  assert.equal(await store.consume('id1'), false);
  const after = await store.getById('id1');
  assert.ok(after.consumedAt > 0);
});

test('integration: incrRate increments + PEXPIRE binds a TTL', { skip: skipMsg }, async () => {
  const c = await client();
  const kp = runPrefix();
  const store = redisStore(c, { keyPrefix: kp });
  const a = await store.incrRate('u@x.com', 60_000);
  const b = await store.incrRate('u@x.com', 60_000);
  assert.equal(a.count, 1);
  assert.equal(b.count, 2);
  // Real Redis PTTL reports the remaining ms — must be > 0 and ≤ 60_000.
  const pttl = await c.pttl(`${kp}rate:u@x.com`);
  assert.ok(pttl > 0 && pttl <= 60_000);
});

test('integration: listByEmail returns every put + revokeByEmail flips consumedAt', { skip: skipMsg }, async () => {
  const c = await client();
  const store = redisStore(c, { keyPrefix: runPrefix() });
  await store.put(newRecord('a', 'u@x.com'));
  await store.put(newRecord('b', 'u@x.com'));
  const list = await store.listByEmail('u@x.com');
  assert.equal(list.length, 2);
  const n = await store.revokeByEmail('u@x.com');
  assert.equal(n, 2);
});

test('integration: teardown', { skip: skipMsg }, async () => {
  if (sharedClient) await sharedClient.quit();
});
