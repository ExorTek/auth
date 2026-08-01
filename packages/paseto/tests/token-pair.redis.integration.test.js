/**
 * Live-Redis integration for the token-pair layer. Skipped unless
 * REDIS_URL is set — exercises the atomic `markUsed` (Lua CAS) rotation
 * and cross-process reuse detection that the mock cannot cover.
 *
 * Run locally against Docker:
 *   docker run --rm -p 6379:6379 redis:8.4.0-alpine
 *   REDIS_URL=redis://localhost:6379 node --test \
 *     packages/paseto/tests/token-pair.redis.integration.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { create, rotate } from '../src/token-pair.js';
import { createStore } from '../src/stores.js';
import { decrypt, generateKey, PasetoError, ErrorCode } from '../src/index.js';

const REDIS_URL = process.env.REDIS_URL;

if (!REDIS_URL) {
  test('redis integration (skipped — set REDIS_URL to enable)', { skip: true }, () => {});
} else {
  const { default: Redis } = await import('ioredis');

  const client = new Redis(REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1 });
  await client.connect();
  const runNs = `paseto-test:${process.pid}:${Date.now()}:`;

  test.after(async () => {
    const scanned = await client.keys(`${runNs}*`);
    if (scanned.length) {
      await client.del(...scanned);
    }
    await client.quit();
  });

  const mkOpts = () => ({
    secret: { access: generateKey() },
    access: { expiresIn: '15m' },
    refresh: { expiresIn: '7d', store: createStore('redis', { client, keyPrefix: runNs }) },
  });

  test('redis: create → rotate issues a fresh pair, preserves family', async () => {
    const opts = mkOpts();
    const first = await create({ userId: 1 }, opts);
    const second = await rotate(first.refreshToken, opts);
    assert.notEqual(second.refreshToken, first.refreshToken);
    assert.equal(second.familyId, first.familyId);
    assert.equal(decrypt(second.accessToken, opts.secret.access).userId, 1);
  });

  test('redis: replaying a rotated refresh revokes the family via Lua CAS', async () => {
    const opts = mkOpts();
    const first = await create({ userId: 2 }, opts);
    await rotate(first.refreshToken, opts);
    await assert.rejects(
      () => rotate(first.refreshToken, opts),
      err => err instanceof PasetoError && err.code === ErrorCode.REFRESH_REUSED,
    );
  });
}
