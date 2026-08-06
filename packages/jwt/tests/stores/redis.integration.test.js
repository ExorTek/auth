/**
 * Live-Redis integration for the blacklist / refresh registry.
 *
 * Runs against both supported clients — `ioredis` and `node-redis` — because
 * the store branches on the detected dialect for Lua and SET-with-TTL, and a
 * single-driver suite cannot see a mistake in the other branch.
 *
 * Local run:
 *
 *   docker run --rm -d --name auth-redis -p 6379:6379 redis:8.4.0-alpine
 *   REDIS_URL=redis://127.0.0.1:6379 yarn workspace @exortek/jwt test
 */

import assert from 'node:assert/strict';

import { forEachRedisDriver } from '@exortek/shared/test-helpers/redis-drivers';

import { createStore } from '../../src/stores.js';

const nowSec = () => Math.floor(Date.now() / 1000);

forEachRedisDriver('jwt redis store', ({ test, client, ns }) => {
  test('add + has + get round trip', async () => {
    const store = createStore('redis', { client: client(), keyPrefix: ns('a') });
    await store.add('jti-1', nowSec() + 60, { userId: 'u1' });

    assert.equal(await store.has('jti-1'), true);
    assert.equal(await store.has('jti-absent'), false);

    const record = await store.get('jti-1');
    assert.equal(record.metadata.userId, 'u1');
  });

  test('markUsed flips the record once and reports reuse on the second call', async () => {
    const store = createStore('redis', { client: client(), keyPrefix: ns('b') });
    await store.add('jti-2', nowSec() + 60, {});

    const first = await store.markUsed('jti-2', nowSec());
    assert.equal(first.swapped, true, 'first markUsed should win the CAS');

    const second = await store.markUsed('jti-2', nowSec());
    assert.equal(second.swapped, false, 'second markUsed must report the token as already used');
  });

  test('markUsed on an absent key resolves to null', async () => {
    const store = createStore('redis', { client: client(), keyPrefix: ns('c') });
    assert.equal(await store.markUsed('never-added', nowSec()), null);
  });

  test('delete removes the entry', async () => {
    const store = createStore('redis', { client: client(), keyPrefix: ns('d') });
    await store.add('jti-3', nowSec() + 60, {});
    await store.delete('jti-3');
    assert.equal(await store.has('jti-3'), false);
  });

  test('deleteAll sweeps entries matching a metadata filter', async () => {
    const store = createStore('redis', { client: client(), keyPrefix: ns('e') });
    await store.add('keep', nowSec() + 60, { familyId: 'f2' });
    await store.add('drop-1', nowSec() + 60, { familyId: 'f1' });
    await store.add('drop-2', nowSec() + 60, { familyId: 'f1' });

    assert.equal(await store.deleteAll({ familyId: 'f1' }), 2);
    assert.equal(await store.has('drop-1'), false);
    assert.equal(await store.has('keep'), true, 'a non-matching entry must survive');
  });
});
