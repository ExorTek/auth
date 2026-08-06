/**
 * Live-Redis integration for the rate-limit counter store.
 *
 * Runs against both supported clients — `ioredis` and `node-redis`. The
 * counter is a Lua script, and the two drivers take their `eval` arguments
 * differently, so a single-driver suite cannot see a mistake in the other
 * branch.
 *
 * Local run:
 *
 *   docker run --rm -d --name auth-redis -p 6379:6379 redis:8.4.0-alpine
 *   REDIS_URL=redis://127.0.0.1:6379 yarn workspace @exortek/challenge test
 */

import assert from 'node:assert/strict';

import { forEachRedisDriver } from '@exortek/shared/test-helpers/redis-drivers';

import { redisStore } from '../../src/stores/redis.js';

forEachRedisDriver('challenge redis store', ({ test, client, ns }) => {
  test('incr counts up from one and reports a future expiry', async () => {
    const store = redisStore(client(), { keyPrefix: ns('a') });

    const first = await store.incr('user-1', 60_000);
    assert.equal(first.count, 1);
    assert.ok(first.expiresAt > Date.now(), 'expiresAt should be in the future');

    const second = await store.incr('user-1', 60_000);
    assert.equal(second.count, 2, 'the counter must be shared across calls');
  });

  test('separate keys keep independent counters', async () => {
    const store = redisStore(client(), { keyPrefix: ns('b') });

    await store.incr('user-a', 60_000);
    await store.incr('user-a', 60_000);
    const other = await store.incr('user-b', 60_000);

    assert.equal(other.count, 1, 'a different key must start its own counter');
  });

  test('the TTL is bound on the first increment', async () => {
    const store = redisStore(client(), { keyPrefix: ns('c') });

    const { expiresAt } = await store.incr('user-ttl', 5_000);
    const remaining = expiresAt - Date.now();

    assert.ok(remaining > 0 && remaining <= 5_000, `expected a bounded TTL, got ${remaining}ms`);
  });
});
