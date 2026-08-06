/**
 * Redis client-shape compatibility helpers.
 *
 * ioredis, node-redis v4+, and @upstash/redis all expose the same
 * operations under slightly different names and calling conventions.
 * This module creates a normalised adapter so every store in the repo
 * can share a single detection path instead of copy-pasting the same
 * three-way dispatch.
 *
 * Internal to `@exortek/shared` — consumed by `incr-store.js` and
 * `record-store.js`, not re-exported to consuming packages.
 */

import { isFunction, isString } from './predicates.js';

/**
 * Which calling convention a client expects for the commands whose
 * signatures differ between drivers — Lua (`eval`) and `SET` with a TTL.
 *
 * Most helpers here can dispatch on a method name (`mget` vs `mGet`), but
 * these two share a name and differ only in how arguments are passed, so
 * they need an explicit answer.
 *
 * A real `ioredis` instance reports `constructor.name === 'EventEmitter'`
 * — it extends EventEmitter and no class name survives to the instance —
 * so a constructor-name probe alone never matches it. Detect on the API
 * surface instead (`scanStream` / the `status` string), neither of which
 * node-redis has, and keep the name check as a fallback for wrapped
 * clients. Anything unrecognised is treated as node-redis, whose
 * options-object form is also what `@upstash/redis` accepts.
 *
 * @param {any} client
 * @returns {'ioredis' | 'node-redis'}
 */
export function detectDialect(client) {
  if (client && (isFunction(client.scanStream) || isString(client.status))) {
    return 'ioredis';
  }
  const name = (client && client.constructor && client.constructor.name) || '';
  if (name === 'Redis' || name === 'Cluster') {
    return 'ioredis';
  }
  return 'node-redis';
}

/**
 * Run a Lua script, passing its keys and arguments the way `client`
 * expects.
 *
 * Getting this wrong is silent on node-redis: handed the ioredis
 * positional form it does not throw, it sends `EVAL <script> 0` and the
 * script runs against an empty `KEYS`/`ARGV`.
 *
 * @param {any} client
 * @param {string} script
 * @param {string[]} keys
 * @param {string[]} args
 * @param {'ioredis' | 'node-redis'} [dialect]
 * @returns {Promise<any>}
 */
export function evalScript(client, script, keys, args, dialect = detectDialect(client)) {
  return dialect === 'ioredis'
    ? client.eval(script, keys.length, ...keys, ...args)
    : client.eval(script, { keys, arguments: args });
}

/**
 * @param {object} client  A Redis-compatible client instance.
 * @returns {{
 *   mget: (keys: string[]) => Promise<(string|null)[]>,
 *   sadd: (key: string, member: string) => Promise<any>,
 *   srem: (key: string, member: string) => Promise<any>,
 *   smembers: (key: string) => Promise<string[]>,
 *   setWithTTL: (key: string, value: string, ttlMs: number) => Promise<void>,
 *   setPlain: (key: string, value: string) => Promise<void>,
 *   parseRecord: (raw: string|object|null) => object|null,
 * }}
 */
export function createRedisHelpers(client) {
  const dialect = detectDialect(client);

  return {
    dialect,

    async mget(keys) {
      if (keys.length === 0) {
        return [];
      }
      if (isFunction(client.mget)) {
        return client.mget(...keys);
      }
      if (isFunction(client.mGet)) {
        return client.mGet(keys);
      }
      return Promise.all(keys.map(k => client.get(k)));
    },

    async sadd(key, member) {
      if (isFunction(client.sadd)) {
        return client.sadd(key, member);
      }
      if (isFunction(client.sAdd)) {
        return client.sAdd(key, member);
      }
      return null;
    },

    async srem(key, member) {
      if (isFunction(client.srem)) {
        return client.srem(key, member);
      }
      if (isFunction(client.sRem)) {
        return client.sRem(key, member);
      }
      return null;
    },

    async smembers(key) {
      if (isFunction(client.smembers)) {
        return client.smembers(key);
      }
      if (isFunction(client.sMembers)) {
        return client.sMembers(key);
      }
      return [];
    },

    async setWithTTL(key, value, ttlMs) {
      const px = Math.max(1, Math.ceil(ttlMs));
      // Must dispatch on the dialect, not on a try/catch: node-redis accepts
      // the ioredis positional form without complaint and simply stores the
      // key with no expiry, so a catch-based fallback never fires and the TTL
      // is silently dropped.
      if (dialect === 'ioredis') {
        await client.set(key, value, 'PX', px);
      } else {
        await client.set(key, value, { PX: px });
      }
    },

    async setPlain(key, value) {
      await client.set(key, value);
    },

    parseRecord(raw) {
      if (!raw) {
        return null;
      }
      try {
        return isString(raw) ? JSON.parse(raw) : raw;
      } catch {
        return null;
      }
    },
  };
}
