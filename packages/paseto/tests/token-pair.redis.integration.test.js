/**
 * Live-Redis integration for the token-pair layer, run against both
 * supported clients. Skipped unless REDIS_URL is set — exercises the atomic
 * `markUsed` (Lua CAS) rotation and cross-process reuse detection that the
 * mock cannot cover, and the two drivers pass `eval` arguments differently.
 *
 * Run locally against Docker:
 *   docker run --rm -d --name auth-redis -p 6379:6379 redis:8.4.0-alpine
 *   REDIS_URL=redis://localhost:6379 node --test \
 *     packages/paseto/tests/token-pair.redis.integration.test.js
 */

import assert from 'node:assert/strict';

import { forEachRedisDriver } from '@exortek/shared/test-helpers/redis-drivers';

import { create, rotate } from '../src/token-pair.js';
import { createStore } from '../src/stores.js';
import { decrypt, generateKey, PasetoError, ErrorCode } from '../src/index.js';

forEachRedisDriver('paseto token-pair over redis', ({ test, client, ns }) => {
  const mkOpts = suffix => ({
    secret: { access: generateKey() },
    access: { expiresIn: '15m' },
    refresh: {
      expiresIn: '7d',
      store: createStore('redis', { client: client(), keyPrefix: ns(suffix) }),
    },
  });

  test('create → rotate issues a fresh pair and preserves the family', async () => {
    const opts = mkOpts('a');
    const first = await create({ userId: 1 }, opts);
    const second = await rotate(first.refreshToken, opts);

    assert.notEqual(second.refreshToken, first.refreshToken);
    assert.equal(second.familyId, first.familyId);
    assert.equal(decrypt(second.accessToken, opts.secret.access).userId, 1);
  });

  test('replaying a rotated refresh revokes the family via Lua CAS', async () => {
    const opts = mkOpts('b');
    const first = await create({ userId: 2 }, opts);
    await rotate(first.refreshToken, opts);

    await assert.rejects(
      () => rotate(first.refreshToken, opts),
      err => err instanceof PasetoError && err.code === ErrorCode.REFRESH_REUSED,
    );
  });
});
