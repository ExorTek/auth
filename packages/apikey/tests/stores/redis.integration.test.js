/**
 * Integration test — runs against a real Redis when `REDIS_URL` is
 * set. Skipped otherwise so a fresh clone can `yarn test` without
 * Docker.
 *
 * Local run:
 *
 *   docker run --rm -d --name auth-redis -p 6379:6379 redis:8.4.0-alpine
 *   REDIS_URL=redis://127.0.0.1:6379 yarn workspace @exortek/apikey test
 *
 * Covers the client-boundary code the fake-client suite can't touch:
 * real ioredis's argument-splat (`sadd(k, ...ids)`), actual JSON
 * round-trip, real EXISTS semantics.
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

let sharedClient = null;
async function client() {
  if (!sharedClient) sharedClient = new ioredis(REDIS_URL, { lazyConnect: true });
  return sharedClient;
}

// Random key prefix per run so parallel test runs don't collide.
const runPrefix = () => `apikey:test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}:`;

test('integration: put + getById round-trip', { skip: skipMsg }, async () => {
  const c = await client();
  const store = redisStore(c, { keyPrefix: runPrefix() });
  await store.put(newRecord('id1', 'u1'));
  const back = await store.getById('id1');
  assert.equal(back.id, 'id1');
  assert.equal(back.userId, 'u1');
  assert.equal(back.prefix, 'sk_live');
});

test('integration: revoke round-trip', { skip: skipMsg }, async () => {
  const c = await client();
  const store = redisStore(c, { keyPrefix: runPrefix() });
  await store.put(newRecord('id1', 'u1'));
  assert.equal(await store.revoke('id1', 'why'), true);
  const back = await store.getById('id1');
  assert.ok(back.revokedAt > 0);
  assert.equal(back.revokedReason, 'why');
  assert.equal(await store.revoke('id1'), false);
});

test('integration: revokeAllForUser + listByUser', { skip: skipMsg }, async () => {
  const c = await client();
  const store = redisStore(c, { keyPrefix: runPrefix() });
  await store.put(newRecord('a', 'u'));
  await store.put(newRecord('b', 'u'));
  await store.put(newRecord('c', 'u2'));
  const list = await store.listByUser('u');
  assert.equal(list.length, 2);
  const n = await store.revokeAllForUser('u');
  assert.equal(n, 2);
  const other = await store.listByUser('u2');
  assert.equal(other.length, 1);
});

test('integration: update userId reshuffles the reverse index', { skip: skipMsg }, async () => {
  const c = await client();
  const store = redisStore(c, { keyPrefix: runPrefix() });
  await store.put(newRecord('id1', 'u1'));
  await store.update('id1', { userId: 'u2' });
  assert.deepEqual(await store.listByUser('u1'), []);
  const rows = await store.listByUser('u2');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].id, 'id1');
});

// Clean shutdown — quit the shared connection so `node --test` exits.
test('integration: teardown', { skip: skipMsg }, async () => {
  if (sharedClient) await sharedClient.quit();
});
