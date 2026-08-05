/**
 * Integration test — runs against a real Redis when `REDIS_URL` is
 * set, against both supported clients. Skipped otherwise so a fresh
 * clone can `yarn test` without Docker.
 *
 * Local run:
 *
 *   docker run --rm -d --name auth-redis -p 6379:6379 redis:8.4.0-alpine
 *   REDIS_URL=redis://127.0.0.1:6379 yarn workspace @exortek/apikey test
 *
 * Covers the client-boundary code the fake-client suite can't touch:
 * the real argument-splat on set commands, actual JSON round-trip, real
 * EXISTS semantics — all of which the two drivers spell differently.
 */

import assert from 'node:assert/strict';

import { forEachRedisDriver } from '@exortek/shared/test-helpers/redis-drivers';

import { redisStore } from '../../src/stores/redis.js';

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

forEachRedisDriver('apikey redis store', ({ test, client, ns }) => {
  test('put + getById round-trip', async () => {
    const store = redisStore(client(), { keyPrefix: ns('a') });
    await store.put(newRecord('id1', 'u1'));

    const back = await store.getById('id1');
    assert.equal(back.id, 'id1');
    assert.equal(back.userId, 'u1');
    assert.equal(back.prefix, 'sk_live');
  });

  test('revoke round-trip', async () => {
    const store = redisStore(client(), { keyPrefix: ns('b') });
    await store.put(newRecord('id1', 'u1'));

    assert.equal(await store.revoke('id1', 'why'), true);
    const back = await store.getById('id1');
    assert.ok(back.revokedAt > 0);
    assert.equal(back.revokedReason, 'why');

    assert.equal(await store.revoke('id1'), false, 'a second revoke must be a no-op');
  });

  test('revokeAllForUser + listByUser', async () => {
    const store = redisStore(client(), { keyPrefix: ns('c') });
    await store.put(newRecord('a', 'u'));
    await store.put(newRecord('b', 'u'));
    await store.put(newRecord('c', 'u2'));

    assert.equal((await store.listByUser('u')).length, 2);
    assert.equal(await store.revokeAllForUser('u'), 2);
    assert.equal((await store.listByUser('u2')).length, 1, 'another user must be untouched');
  });

  test('update userId reshuffles the reverse index', async () => {
    const store = redisStore(client(), { keyPrefix: ns('d') });
    await store.put(newRecord('id1', 'u1'));
    await store.update('id1', { userId: 'u2' });

    assert.deepEqual(await store.listByUser('u1'), []);
    const rows = await store.listByUser('u2');
    assert.equal(rows.length, 1);
    assert.equal(rows[0].id, 'id1');
  });
});
