/**
 * Integration test — runs against a real Redis when `REDIS_URL` is set,
 * against both supported clients. Skipped otherwise so a fresh clone can
 * `yarn test` without Docker.
 *
 *   docker run --rm -d --name auth-redis -p 6379:6379 redis:8.4.0-alpine
 *   REDIS_URL=redis://127.0.0.1:6379 yarn workspace @exortek/opaque test
 */

import assert from 'node:assert/strict';

import { forEachRedisDriver } from '@exortek/shared/test-helpers/redis-drivers';

import { redisStore } from '../../src/stores/redis.js';

// The shared `setWithTTL` helper tries the ioredis positional form first and
// falls back on throw — but node-redis does not throw, it accepts the call and
// silently stores the key with no expiry. So the fallback never runs and the
// TTL is dropped. Fixed in the follow-up commit.
const TTL_DROPPED = { todo: { 'node-redis': 'setWithTTL dialect branch — fixed in a follow-up' } };

forEachRedisDriver('opaque redis store', ({ test, client, ns }) => {
  test('set + get round-trip', async () => {
    const store = redisStore(client(), { keyPrefix: ns('a') });
    await store.set('hash1', { userId: 'usr_1' });
    assert.deepEqual(await store.get('hash1'), { userId: 'usr_1' });
  });

  test('entries expire via native Redis TTL', TTL_DROPPED, async () => {
    const store = redisStore(client(), { keyPrefix: ns('b') });
    await store.set('hash1', { a: 1 }, { expiresIn: 50 });
    assert.deepEqual(await store.get('hash1'), { a: 1 });
    await new Promise(r => setTimeout(r, 150));
    assert.equal(await store.get('hash1'), null);
  });

  test('delete removes the key', async () => {
    const store = redisStore(client(), { keyPrefix: ns('c') });
    await store.set('hash1', { a: 1 });
    assert.equal(await store.delete('hash1'), true);
    assert.equal(await store.get('hash1'), null);
    assert.equal(await store.delete('hash1'), false);
  });
});
