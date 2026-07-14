import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redisStore } from '../../src/stores/redis.js';

// Live-Redis integration test. Skipped unless REDIS_URL is set.
//
// Run locally against Docker:
//   docker run --rm -d --name auth-redis -p 6379:6379 redis:8.4.0-alpine
//   REDIS_URL=redis://localhost:6379 node --test \
//     packages/session/tests/stores/redis.integration.test.js

const REDIS_URL = process.env.REDIS_URL;

if (!REDIS_URL) {
  test('redis integration (skipped — set REDIS_URL to enable)', { skip: true }, () => {});
} else {
  const { default: Redis } = await import('ioredis');

  const client = new Redis(REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1 });
  await client.connect();
  // Isolate this test run from anything else on the same server.
  const runNs = `sess-test:${process.pid}:${Date.now()}:`;

  test.after(async () => {
    const scanned = await client.keys(`${runNs}*`);
    if (scanned.length) {
      await client.del(...scanned);
    }
    await client.quit();
  });

  function makeRecord(overrides = {}) {
    const now = Date.now();
    return {
      sid: 's1',
      uid: 'u1',
      claims: {},
      issuedAt: now,
      expiresAt: now + 60_000,
      lastSeenAt: now,
      isAnonymous: false,
      revoked: false,
      ...overrides,
    };
  }

  test('redis: put + get + revoke round trip', async () => {
    const store = redisStore(client, { keyPrefix: `${runNs}a:` });
    await store.put(makeRecord({ sid: 'x' }));
    assert.equal((await store.get('x')).sid, 'x');
    assert.equal(await store.revoke('x', 'logout'), true);
    const got = await store.get('x');
    assert.equal(got.revoked, true);
    assert.equal(got.revokedReason, 'logout');
  });

  test('redis: revocation survives a racing lost-update from update()', async () => {
    const prefix = `${runNs}b:`;
    const store = redisStore(client, { keyPrefix: prefix });
    await store.put(makeRecord({ sid: 'x' }));

    // Worker A reads the pre-revoke copy...
    const stale = JSON.parse(await client.get(`${prefix}x`));
    // ...worker B revokes...
    await store.revoke('x', 'stolen');
    // ...and worker A's write lands last with revoked: false.
    await client.set(`${prefix}x`, JSON.stringify({ ...stale, lastSeenAt: Date.now() }), 'PX', 60_000);

    const got = await store.get('x');
    assert.equal(got.revoked, true, 'tombstone must keep the session revoked');
  });

  test('redis: user index gets a TTL (no permanent u:<uid> sets)', async () => {
    const prefix = `${runNs}c:`;
    const store = redisStore(client, { keyPrefix: prefix });
    await store.put(makeRecord({ sid: 'x', uid: 'u9' }));
    const pttl = await client.pttl(`${prefix}u:u9`);
    assert.ok(pttl > 0, `expected a positive PTTL on the user index; got ${pttl}`);
    assert.ok(pttl <= 60_000, `TTL should match the session lifetime; got ${pttl}`);
  });

  test('redis: index TTL only ever extends (GT semantics)', async () => {
    const prefix = `${runNs}d:`;
    const store = redisStore(client, { keyPrefix: prefix });
    await store.put(makeRecord({ sid: 'long', uid: 'u9', expiresAt: Date.now() + 120_000 }));
    const before = await client.pttl(`${prefix}u:u9`);
    // A shorter-lived session must not shorten the index TTL.
    await store.put(makeRecord({ sid: 'short', uid: 'u9', expiresAt: Date.now() + 5_000 }));
    const after = await client.pttl(`${prefix}u:u9`);
    assert.ok(after >= before - 1_000, `index TTL shrank from ${before} to ${after}`);
  });

  test('redis: listByUser batches via MGET and prunes dead index entries', async () => {
    const prefix = `${runNs}e:`;
    const store = redisStore(client, { keyPrefix: prefix });
    await store.put(makeRecord({ sid: 'x', uid: 'u5' }));
    await store.put(makeRecord({ sid: 'y', uid: 'u5' }));
    // Simulate an expired record whose sid lingers in the set.
    await client.sadd(`${prefix}u:u5`, 'ghost');
    const list = await store.listByUser('u5');
    assert.deepEqual(list.map(r => r.sid).sort(), ['x', 'y']);
    const members = await client.smembers(`${prefix}u:u5`);
    assert.ok(!members.includes('ghost'), 'dead index entry should be pruned');
  });
}
