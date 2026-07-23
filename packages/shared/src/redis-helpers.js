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
  return {
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
      try {
        await client.set(key, value, 'PX', px);
      } catch {
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
