/**
 * Redis-backed store for challenge single-use enforcement.
 *
 * Cluster-safe: state lives in Redis, so a challenge accepted on one
 * worker cannot be replayed on another. Works with any client exposing
 * `eval(script, numkeys, ...args)` — verified against `ioredis`,
 * `node-redis` v4+, and `@upstash/redis` (HTTP client, runs on
 * Cloudflare Workers / Vercel Edge / Deno Deploy).
 *
 * Atomicity: `incr` runs a single Lua script that INCR's the key and
 * PEXPIRE's it only when the key is fresh (count === 1). The TTL
 * anchors to the first increment — exactly what single-use enforcement
 * needs (the tombstone lives as long as the token could still verify,
 * then rolls off).
 */

import { assertRedisClient } from '@exortek/shared/redis-guard';

import { invalidArgument } from '../internal/guards.js';

const INCR_SCRIPT = `
local key = KEYS[1]
local ttl = tonumber(ARGV[1])
local count = redis.call('INCR', key)
local pttl
if count == 1 then
  redis.call('PEXPIRE', key, ttl)
  pttl = ttl
else
  pttl = redis.call('PTTL', key)
  if pttl < 0 then
    redis.call('PEXPIRE', key, ttl)
    pttl = ttl
  end
end
return { count, pttl }
`.trim();

/**
 * @typedef {object} RedisStoreOptions
 * @property {string} [keyPrefix='chall:']   Prepended to every key.
 */

/**
 * @param {any} client
 * @param {RedisStoreOptions} [options]
 * @returns {import('./index.js').IncrStore}
 */
export function redisStore(client, options = {}) {
  assertRedisClient(client, ['eval'], msg => {
    throw invalidArgument(`redisStore.client: ${msg}`);
  });
  const keyPrefix = options.keyPrefix ?? 'chall:';
  const k = key => `${keyPrefix}${key}`;

  return {
    async incr(key, ttlMs) {
      const raw = await client.eval(INCR_SCRIPT, 1, k(key), String(Math.max(1, Math.ceil(ttlMs))));
      // ioredis returns [count, pttl] as numbers; node-redis v4 does too;
      // Upstash HTTP driver returns strings. Coerce defensively.
      const arr = Array.isArray(raw) ? raw : [raw, ttlMs];
      const count = Number(arr[0]);
      const pttl = Number(arr[1]);
      return { count, expiresAt: Date.now() + (Number.isFinite(pttl) && pttl > 0 ? pttl : ttlMs) };
    },
  };
}
