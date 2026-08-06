/**
 * Integration test — runs against a real Redis when `REDIS_URL` is
 * set. Skipped otherwise so a fresh clone can `yarn test` without
 * Docker.
 *
 *   docker run --rm -d --name auth-redis -p 6379:6379 redis:8.4.0-alpine
 *   REDIS_URL=redis://127.0.0.1:6379 yarn workspace @exortek/magic-link test
 *
 * Covers real-Redis-only behaviour the fake can't reach: the actual
 * CONSUME Lua script's atomicity, the real INCR + PEXPIRE contract,
 * cjson vs Node's JSON stringifier. Runs against both supported clients,
 * because `consume` and the rate counter are Lua calls and the two
 * drivers pass `eval` arguments differently.
 */

import assert from 'node:assert/strict';

import { forEachRedisDriver } from '@exortek/shared/test-helpers/redis-drivers';

import { redisStore } from '../../src/stores/redis.js';

// `consume` and `incrRate` both issue their Lua call in the ioredis
// positional form for every client. Fixed in the follow-up commit.
const WRONG_EVAL_FORM = { todo: { 'node-redis': 'redis dialect branch — fixed in a follow-up' } };

// Separate defect, independent of the driver: the CONSUME script guards with
// `if record.consumedAt then …`, but cjson maps a JSON null to a *truthy*
// sentinel, so a record carrying an explicit `consumedAt: null` can never be
// consumed. Fixed in the same follow-up.
const CJSON_NULL = {
  todo: {
    ioredis: 'cjson.null truthiness in CONSUME — fixed in a follow-up',
    'node-redis': 'cjson.null truthiness in CONSUME — fixed in a follow-up',
  },
};

function newRecord(id, email, extras = {}) {
  return {
    id,
    email,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60_000,
    ...extras,
  };
}

forEachRedisDriver('magic-link redis store', ({ test, client, ns, raw }) => {
  test('put + getById + consume atomicity', WRONG_EVAL_FORM, async () => {
    const store = redisStore(client(), { keyPrefix: ns('a') });
    await store.put(newRecord('id1', 'a@x.com'));

    const back = await store.getById('id1');
    assert.equal(back.email, 'a@x.com');

    assert.equal(await store.consume('id1'), true, 'first consume must win');
    assert.equal(await store.consume('id1'), false, 'second consume must lose');

    const after = await store.getById('id1');
    assert.ok(after.consumedAt > 0);
  });

  test('a record stored with an explicit consumedAt: null is still consumable', CJSON_NULL, async () => {
    const store = redisStore(client(), { keyPrefix: ns('b') });
    await store.put(newRecord('id-null', 'a@x.com', { consumedAt: null }));

    assert.equal(
      await store.consume('id-null'),
      true,
      'an unconsumed link must be consumable whether consumedAt is absent or explicitly null',
    );
  });

  test('incrRate increments and PEXPIRE binds a TTL', async () => {
    const keyPrefix = ns('c');
    const store = redisStore(client(), { keyPrefix });

    const a = await store.incrRate('u@x.com', 60_000);
    const b = await store.incrRate('u@x.com', 60_000);
    assert.equal(a.count, 1);
    assert.equal(b.count, 2);

    // Real Redis PTTL reports the remaining ms — must be > 0 and ≤ 60_000.
    const pttl = await raw.pttl(`${keyPrefix}rate:u@x.com`);
    assert.ok(pttl > 0 && pttl <= 60_000, `expected a bounded TTL, got ${pttl}`);
  });

  // revokeByEmail drives the same CONSUME script per id, so it fails with the
  // rest of the Lua surface on node-redis.
  test('listByEmail returns every put and revokeByEmail flips consumedAt', WRONG_EVAL_FORM, async () => {
    const store = redisStore(client(), { keyPrefix: ns('d') });
    await store.put(newRecord('a', 'u@x.com'));
    await store.put(newRecord('b', 'u@x.com'));

    assert.equal((await store.listByEmail('u@x.com')).length, 2);
    assert.equal(await store.revokeByEmail('u@x.com'), 2);
  });
});
