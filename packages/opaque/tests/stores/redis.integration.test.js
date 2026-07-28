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

const runPrefix = () => `opaque:test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}:`;

test('integration: set + get round-trip', { skip: skipMsg }, async () => {
  const c = await client();
  const store = redisStore(c, { keyPrefix: runPrefix() });
  await store.set('hash1', { userId: 'usr_1' });
  assert.deepEqual(await store.get('hash1'), { userId: 'usr_1' });
});

test('integration: entries expire via native Redis TTL', { skip: skipMsg }, async () => {
  const c = await client();
  const store = redisStore(c, { keyPrefix: runPrefix() });
  await store.set('hash1', { a: 1 }, { expiresIn: 50 });
  assert.deepEqual(await store.get('hash1'), { a: 1 });
  await new Promise(r => setTimeout(r, 150));
  assert.equal(await store.get('hash1'), null);
});

test('integration: delete removes the key', { skip: skipMsg }, async () => {
  const c = await client();
  const store = redisStore(c, { keyPrefix: runPrefix() });
  await store.set('hash1', { a: 1 });
  assert.equal(await store.delete('hash1'), true);
  assert.equal(await store.get('hash1'), null);
  assert.equal(await store.delete('hash1'), false);
});

test('integration: teardown', { skip: skipMsg }, async () => {
  if (sharedClient) await sharedClient.quit();
});
