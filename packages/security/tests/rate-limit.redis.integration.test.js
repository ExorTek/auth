import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rateLimit } from '../src/index.js';

// Live-Redis integration test. Skipped unless REDIS_URL is set.
//
// Run locally against Docker:
//   docker run --rm -p 6379:6379 redis:8.4.0-alpine
//   REDIS_URL=redis://localhost:6379 node --test \
//     packages/security/tests/rate-limit.redis.integration.test.js

const REDIS_URL = process.env.REDIS_URL;

if (!REDIS_URL) {
  test('redis integration (skipped — set REDIS_URL to enable)', { skip: true }, () => {});
} else {
  const { default: Redis } = await import('ioredis');

  const client = new Redis(REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1 });
  await client.connect();
  // Isolate this test run from anything else on the same server.
  const runNs = `rl-test:${process.pid}:${Date.now()}:`;

  test.after(async () => {
    // Sweep any keys this run left behind.
    const scanned = await client.keys(`${runNs}*`);
    if (scanned.length) {
      await client.del(...scanned);
    }
    await client.quit();
  });

  test('redis: incr increments atomically and returns count/expiresAt', async () => {
    const store = rateLimit.stores.redis(client, { prefix: `${runNs}incr:` });
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

  test('redis: defineCommand path registered (ioredis EVALSHA)', async () => {
    const store = rateLimit.stores.redis(client, { prefix: `${runNs}defcmd:` });
    await store.incr('k', 1000);
    assert.equal(typeof client.exortekRlIncr, 'function');
    assert.equal(typeof client.exortekRlRead, 'function');
  });

  test('redis: read is non-mutating', async () => {
    const store = rateLimit.stores.redis(client, { prefix: `${runNs}read:` });
    await store.incr('k', 5000);
    const a = await store.read('k');
    const b = await store.read('k');
    assert.equal(a.count, 1);
    assert.equal(b.count, 1);
    // A follow-up incr should see 2, confirming read didn't touch the counter.
    const c = await store.incr('k', 5000);
    assert.equal(c.count, 2);
  });

  test('redis: read returns null for missing keys', async () => {
    const store = rateLimit.stores.redis(client, { prefix: `${runNs}miss:` });
    assert.equal(await store.read('nope'), null);
    assert.equal(await store.get('nope'), null);
  });

  test('redis: counter expires at TTL boundary', async () => {
    const store = rateLimit.stores.redis(client, { prefix: `${runNs}exp:` });
    await store.incr('k', 500);
    const before = await store.read('k');
    assert.equal(before.count, 1);
    await new Promise(r => setTimeout(r, 700));
    const after = await store.read('k');
    assert.equal(after, null);
  });

  test('redis: delete/reset clear the key', async () => {
    const store = rateLimit.stores.redis(client, { prefix: `${runNs}del:` });
    await store.incr('k', 5000);
    await store.delete('k');
    assert.equal(await store.read('k'), null);
    await store.incr('k', 5000);
    await store.reset('k');
    assert.equal(await store.read('k'), null);
  });

  test('redis: prefix isolates keys between limiters', async () => {
    const a = rateLimit.stores.redis(client, { prefix: `${runNs}a:` });
    const b = rateLimit.stores.redis(client, { prefix: `${runNs}b:` });
    await a.incr('k', 5000);
    await a.incr('k', 5000);
    const aState = await a.read('k');
    const bState = await b.read('k');
    assert.equal(aState.count, 2);
    assert.equal(bState, null);
  });

  test('redis: end-to-end with fixed limiter', async () => {
    const store = rateLimit.stores.redis(client, { prefix: `${runNs}fixed:` });
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

  test('redis: end-to-end with sliding limiter', async () => {
    const store = rateLimit.stores.redis(client, { prefix: `${runNs}sliding:` });
    const limiter = rateLimit.sliding({ requests: 2, window: '10s', store });
    const r1 = await limiter.check({ key: 'ip' });
    const r2 = await limiter.check({ key: 'ip' });
    const r3 = await limiter.check({ key: 'ip' });
    assert.equal(r1.allowed, true);
    assert.equal(r2.allowed, true);
    assert.equal(r3.allowed, false);
  });

  test('redis: concurrent incr calls remain atomic', async () => {
    const store = rateLimit.stores.redis(client, { prefix: `${runNs}race:` });
    const N = 50;
    const results = await Promise.all(Array.from({ length: N }, () => store.incr('k', 5000)));
    const counts = results.map(r => r.count).sort((a, b) => a - b);
    // Every count 1..N must appear exactly once — proves no lost increments.
    for (let i = 0; i < N; i++) {
      assert.equal(counts[i], i + 1);
    }
  });
}
