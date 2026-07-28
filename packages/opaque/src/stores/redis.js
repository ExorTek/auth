/**
 * Redis-backed store for opaque tokens.
 *
 * Layout: `<keyPrefix><hash>` — a JSON blob of the caller's metadata,
 * with Redis's native `PX` TTL doing expiry (no application-level
 * sweep needed, unlike {@link memoryStore}). Cluster-safe: a token
 * created on one worker is immediately visible to every other.
 *
 * Works with any client exposing `get` / `set` / `del` — verified
 * against `ioredis`, `node-redis@4+`, and `@upstash/redis` via the
 * shared cross-client helpers.
 */

import { assertRedisClient } from '@exortek/shared/redis-guard';
import { createRedisHelpers } from '@exortek/shared/redis-helpers';
import { parseDuration } from '@exortek/shared/duration';
import { invalidArgument } from '../internal/guards.js';

/**
 * @typedef {object} RedisStoreOptions
 * @property {string} [keyPrefix='opaque:']
 */

/**
 * @param {any} client
 * @param {RedisStoreOptions} [options]
 * @returns {import('../index.js').OpaqueStore}
 */
export function redisStore(client, options = {}) {
  assertRedisClient(client, ['get', 'set', 'del'], msg => {
    throw invalidArgument(msg);
  });
  const keyPrefix = options.keyPrefix ?? 'opaque:';
  const helpers = createRedisHelpers(client);
  const rk = key => `${keyPrefix}${key}`;

  return {
    async set(key, value, opts = {}) {
      const json = JSON.stringify(value ?? {});
      if (opts.expiresIn !== undefined) {
        await helpers.setWithTTL(rk(key), json, parseDuration(opts.expiresIn));
      } else {
        await helpers.setPlain(rk(key), json);
      }
    },

    async get(key) {
      return helpers.parseRecord(await client.get(rk(key)));
    },

    async delete(key) {
      const removed = await client.del(rk(key));
      return removed > 0;
    },
  };
}
