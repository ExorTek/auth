/**
 * Live-Redis integration for the shared registry store, run against both
 * supported clients. Skipped unless REDIS_URL is set.
 *
 *   docker run --rm -d --name auth-redis -p 6379:6379 redis:8.4.0-alpine
 *   REDIS_URL=redis://localhost:6379 node --test \
 *     packages/shared/tests/registry-store.redis.integration.test.js
 */

import assert from 'node:assert/strict';

import { forEachRedisDriver } from '../test-helpers/redis-drivers.js';
import { createRedisRegistryStore } from '../src/registry-store.js';

class StoreError extends Error {
  constructor(code, message, extra) {
    super(message, extra);
    this.code = code;
  }
}
const binding = { StoreError, storeErrorCode: 'STORE_ERROR', defaultKeyPrefix: 'reg:' };
const future = () => Math.floor(Date.now() / 1000) + 600;

forEachRedisDriver('registry store over redis', ({ test, client, ns, raw }) => {
  const mkStore = suffix => createRedisRegistryStore(binding, { client: client(), keyPrefix: ns(suffix) });

  test('markUsed leaves the stored metadata byte-for-byte intact', async () => {
    const store = mkStore('intact');
    const payload = { roles: [], id: 12345678901234567, ratio: 0.1, nested: { list: [] } };
    await store.add('r', future(), { familyId: 'f', payload, usedAt: null });

    const first = await store.markUsed('r', 1000);
    assert.equal(first.swapped, true);
    assert.deepEqual(first.record.metadata.payload, payload);
    assert.equal(first.record.metadata.usedAt, 1000);

    const again = await store.get('r');
    assert.deepEqual(again.metadata.payload, payload);
    assert.equal(again.metadata.usedAt, 1000);
  });

  test('markUsed swaps exactly once and keeps the TTL', async () => {
    const store = mkStore('once');
    await store.add('r', future(), { familyId: 'f' });
    const results = await Promise.all([1, 2, 3, 4].map(n => store.markUsed('r', n)));
    assert.equal(results.filter(r => r.swapped).length, 1);
    const pttl = Number(await raw.pttl(`${ns('once')}r`));
    assert.ok(pttl > 500_000, `TTL kept (${pttl})`);
  });

  test('markUsed works on a record added without metadata', async () => {
    const store = mkStore('nometa');
    await store.add('r', future());
    const result = await store.markUsed('r', 42);
    assert.equal(result.swapped, true);
    assert.equal(result.record.metadata.usedAt, 42);
    assert.equal((await store.markUsed('r', 43)).swapped, false);
  });

  test('a record stamped by an earlier version stays used', async () => {
    const store = mkStore('legacy');
    const key = `${ns('legacy')}r`;
    await raw.setWithTTL(key, JSON.stringify({ expiresAt: future(), metadata: { familyId: 'f', usedAt: 7 } }), 600_000);
    const result = await store.markUsed('r', 99);
    assert.equal(result.swapped, false);
    assert.equal(result.record.metadata.usedAt, 7);
  });

  test('markUsed on a missing key returns null', async () => {
    assert.equal(await mkStore('missing').markUsed('nope', 1), null);
  });

  test('deleteAll removes matching records, used or not', async () => {
    const store = mkStore('family');
    await store.add('a', future(), { familyId: 'x' });
    await store.add('b', future(), { familyId: 'x' });
    await store.add('c', future(), { familyId: 'y' });
    await store.markUsed('a', 5);
    assert.equal(await store.deleteAll({ familyId: 'x' }), 2);
    assert.equal(await store.has('a'), false);
    assert.equal(await store.has('c'), true);
  });

  test('deleteAll does not treat glob characters in the prefix as wildcards', async () => {
    const wide = createRedisRegistryStore(binding, { client: client(), keyPrefix: `${ns('glob')}*:` });
    const neighbour = createRedisRegistryStore(binding, { client: client(), keyPrefix: `${ns('glob')}other:` });
    await neighbour.add('n', future(), { familyId: 'x' });
    await wide.add('w', future(), { familyId: 'x' });
    assert.equal(await wide.deleteAll({ familyId: 'x' }), 1);
    assert.equal(await neighbour.has('n'), true);
  });
});
