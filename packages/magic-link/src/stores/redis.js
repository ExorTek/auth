/**
 * Redis-backed store for magic links.
 *
 * Layout:
 *
 *   <keyPrefix><id>              — JSON blob of the record
 *   <keyPrefix>e:<email>         — SADD-set of the email's link ids
 *   <keyPrefix>rate:<email>      — per-email rate-limit counter (INCR + PEXPIRE)
 *
 * The record blob carries an EXPIRE tied to `record.expiresAt` so
 * finished links naturally roll off. `consume` runs a Lua CAS that
 * flips `consumedAt` in-place — atomic across workers, no TOCTOU.
 *
 * Cluster-safe. Works with any client exposing `eval` + `get` + `set`
 * + `del` + `sadd` + `srem` + `smembers` — verified against `ioredis`,
 * `node-redis@4+`, and `@upstash/redis` (HTTP client for edge
 * runtimes).
 */

import { assertRedisClient } from '@exortek/shared/redis-guard';
import { isObject, isString } from '@exortek/shared/predicates';
import { createRedisIncrStore } from '@exortek/shared/incr-store';
import { createRedisRecordStore } from '@exortek/shared/record-store';

import { invalidArgument } from '../internal/guards.js';

// Atomic consume: only flips consumedAt if the record exists and
// hasn't been consumed yet. Returns 1 on success, 0 otherwise.
const CONSUME_SCRIPT = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local raw = redis.call('GET', key)
if not raw then
  return 0
end
local record = cjson.decode(raw)
if record.consumedAt then
  return 0
end
record.consumedAt = now
local pttl = redis.call('PTTL', key)
if pttl > 0 then
  redis.call('SET', key, cjson.encode(record), 'PX', pttl)
else
  redis.call('SET', key, cjson.encode(record))
end
return 1
`.trim();

/**
 * @typedef {object} RedisStoreOptions
 * @property {string} [keyPrefix='mlink:']
 */

/**
 * @param {any} client
 * @param {RedisStoreOptions} [options]
 * @returns {import('../index.js').MagicLinkStore}
 */
export function redisStore(client, options = {}) {
  const wrap = msg => { throw invalidArgument(`redisStore.client: ${msg}`); };
  assertRedisClient(client, ['eval', 'get', 'set', 'del'], wrap);

  const keyPrefix = options.keyPrefix ?? 'mlink:';
  const rk = id => `${keyPrefix}${id}`;

  const recordStore = createRedisRecordStore(client, {
    idField: 'id',
    indexField: 'email',
    keyPrefix,
    indexPrefix: 'e:',
    ttl: true,
    wrap,
  });

  const incrStore = createRedisIncrStore(client, { keyPrefix: `${keyPrefix}rate:` }, wrap);

  return {
    async put(record) {
      if (!isObject(record) || !isString(record.id)) {
        throw invalidArgument('redisStore.put.record.id must be a string');
      }
      const now = Date.now();
      const ttlMs = Math.max(1, (record.expiresAt ?? now + 60_000) - now);
      await recordStore.put(record, ttlMs);
    },

    async getById(id) {
      return recordStore.getById(id);
    },

    async consume(id) {
      const raw = await client.eval(CONSUME_SCRIPT, 1, rk(id), String(Date.now()));
      return Number(raw) === 1;
    },

    async listByEmail(email) {
      return recordStore.listByIndex(email);
    },

    async revokeByEmail(email) {
      const pairs = await recordStore.fetchIndexRecords(email);
      let count = 0;
      for (const [id, record] of pairs) {
        if (!record) {
          continue;
        }
        const ok = await this.consume(id);
        if (ok) {
          count += 1;
        }
      }
      return count;
    },

    async incrRate(email, ttlMs) {
      return incrStore.incr(email, ttlMs);
    },
  };
}
