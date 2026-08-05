/**
 * Live-Redis integration test for the rate-limit stores, run against both
 * supported clients. Skipped unless REDIS_URL is set.
 *
 * Run locally against Docker:
 *   docker run --rm -d --name auth-redis -p 6379:6379 redis:8.4.0-alpine
 *   REDIS_URL=redis://localhost:6379 node --test \
 *     packages/security/tests/rate-limit.redis.integration.test.js
 */

import assert from 'node:assert/strict';

import { forEachRedisDriver } from '@exortek/shared/test-helpers/redis-drivers';

import { rateLimit } from '../src/index.js';

forEachRedisDriver('security rate-limit redis store', ({ test, client, ns, raw, driver }) => {
  test('incr increments atomically and returns count/expiresAt', async () => {
    const store = rateLimit.stores.redis(client(), { prefix: ns('incr') });
    const a = await store.incr('k', 5000);
    const b = await store.incr('k', 5000);
    const c = await store.incr('k', 5000);
    assert.equal(a.count, 1);
    assert.equal(b.count, 2);
    assert.equal(c.count, 3);
    assert.ok(a.expiresAt > Date.now());
    // TTL should not extend across calls (fixed-window semantics).
    assert.ok(Math.abs(a.expiresAt - c.expiresAt) < 200);
  });

  // ioredis-only: the store registers its scripts through `defineCommand` so
  // repeat calls go out as EVALSHA. node-redis has no equivalent and takes the
  // plain EVAL path, so there is nothing to assert on that leg.
  test('defineCommand path registered (ioredis EVALSHA)', async t => {
    if (driver !== 'ioredis') {
      return t.skip('ioredis-only optimisation');
    }
    const store = rateLimit.stores.redis(client(), { prefix: ns('defcmd') });
    await store.incr('k', 1000);
    assert.equal(typeof client().exortekRlIncr, 'function');
    assert.equal(typeof client().exortekRlRead, 'function');
  });

  test('read is non-mutating', async () => {
    const store = rateLimit.stores.redis(client(), { prefix: ns('read') });
    await store.incr('k', 5000);
    const a = await store.read('k');
    const b = await store.read('k');
    assert.equal(a.count, 1);
    assert.equal(b.count, 1);
    // A follow-up incr should see 2, confirming read didn't touch the counter.
    const c = await store.incr('k', 5000);
    assert.equal(c.count, 2);
  });

  test('read returns null for missing keys', async () => {
    const store = rateLimit.stores.redis(client(), { prefix: ns('miss') });
    assert.equal(await store.read('nope'), null);
    assert.equal(await store.get('nope'), null);
  });

  test('counter expires at TTL boundary', async () => {
    const store = rateLimit.stores.redis(client(), { prefix: ns('exp') });
    await store.incr('k', 500);
    const before = await store.read('k');
    assert.equal(before.count, 1);
    await new Promise(r => setTimeout(r, 700));
    const after = await store.read('k');
    assert.equal(after, null);
  });

  test('delete/reset clear the key', async () => {
    const store = rateLimit.stores.redis(client(), { prefix: ns('del') });
    await store.incr('k', 5000);
    await store.delete('k');
    assert.equal(await store.read('k'), null);
    await store.incr('k', 5000);
    await store.reset('k');
    assert.equal(await store.read('k'), null);
  });

  test('prefix isolates keys between limiters', async () => {
    const a = rateLimit.stores.redis(client(), { prefix: ns('a') });
    const b = rateLimit.stores.redis(client(), { prefix: ns('b') });
    await a.incr('k', 5000);
    await a.incr('k', 5000);
    const aState = await a.read('k');
    const bState = await b.read('k');
    assert.equal(aState.count, 2);
    assert.equal(bState, null);
  });

  test('end-to-end with fixed limiter', async () => {
    const store = rateLimit.stores.redis(client(), { prefix: ns('fixed') });
    const limiter = rateLimit.fixed({ requests: 3, window: '1m', store });
    const results = [];
    for (let i = 0; i < 4; i++) {
      results.push(await limiter.check({ key: 'ip:1' }));
    }
    assert.equal(results[0].allowed, true);
    assert.equal(results[0].remaining, 2);
    assert.equal(results[2].allowed, true);
    assert.equal(results[2].remaining, 0);
    assert.equal(results[3].allowed, false);
    assert.ok(results[3].retryAfter >= 1);
  });

  test('end-to-end with sliding limiter', async () => {
    const store = rateLimit.stores.redis(client(), { prefix: ns('sliding') });
    const limiter = rateLimit.sliding({ requests: 2, window: '10s', store });
    const r1 = await limiter.check({ key: 'ip' });
    const r2 = await limiter.check({ key: 'ip' });
    const r3 = await limiter.check({ key: 'ip' });
    assert.equal(r1.allowed, true);
    assert.equal(r2.allowed, true);
    assert.equal(r3.allowed, false);
  });

  test('concurrent incr calls remain atomic', async () => {
    const store = rateLimit.stores.redis(client(), { prefix: ns('race') });
    const N = 50;
    const results = await Promise.all(Array.from({ length: N }, () => store.incr('k', 5000)));
    const counts = results.map(r => r.count).sort((a, b) => a - b);
    // Every count 1..N must appear exactly once — proves no lost increments.
    for (let i = 0; i < N; i++) {
      assert.equal(counts[i], i + 1);
    }
  });

  test('decr rolls back an existing key, never creates, never goes negative', async () => {
    const store = rateLimit.stores.redis(client(), { prefix: ns('decr') });
    await store.incr('k', 5000);
    await store.incr('k', 5000);
    await store.decr('k');
    assert.equal((await store.get('k')).count, 1);
    await store.decr('k');
    await store.decr('k'); // clamp at 0
    // count 0 reads back as null through get() (count <= 0 filter) — assert raw
    const stored = await raw.get(`${ns('decr')}k`);
    assert.equal(stored, '0');
    await store.decr('missing');
    assert.equal(await raw.exists(`${ns('decr')}missing`), 0);
  });

  test('compareAndSet is a real CAS', async () => {
    const store = rateLimit.stores.redis(client(), { prefix: ns('cas') });
    assert.equal(await store.compareAndSet('k', null, '5000|1', 5000), true);
    assert.equal(await store.compareAndSet('k', null, '4000|2', 5000), false);
    assert.equal(await store.compareAndSet('k', '5000|1', '4000|2', 5000), true);
    assert.equal(await store.compareAndSet('k', '5000|1', '3000|3', 5000), false);
    assert.equal(await raw.get(`${ns('cas')}k`), '4000|2');
  });

  test('tokenBucket concurrent burst never overspends capacity', async () => {
    const store = rateLimit.stores.redis(client(), { prefix: ns('tb') });
    const limiter = rateLimit.tokenBucket({ capacity: 5, refillRate: 0.001, store });
    const results = await Promise.all(Array.from({ length: 25 }, () => limiter.check({ key: 'u' })));
    assert.equal(results.filter(r => r.allowed).length, 5);
  });
});
