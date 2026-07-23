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

import { createRedisIncrStore } from '@exortek/shared/incr-store';

import { invalidArgument } from '../internal/guards.js';

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
  return createRedisIncrStore(client, { keyPrefix: options.keyPrefix ?? 'chall:' }, msg => {
    throw invalidArgument(`redisStore.client: ${msg}`);
  });
}
