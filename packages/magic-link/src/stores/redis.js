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
import { isFunction, isObject, isString } from '@exortek/shared/predicates';

import { invalidArgument } from '../internal/guards.js';

const INCR_RATE_SCRIPT = `
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
  assertRedisClient(client, ['eval', 'get', 'set', 'del'], msg => {
    throw invalidArgument(`redisStore.client: ${msg}`);
  });
  const keyPrefix = options.keyPrefix ?? 'mlink:';
  const rk = id => `${keyPrefix}${id}`;
  const ek = email => `${keyPrefix}e:${email}`;
  const rateKey = email => `${keyPrefix}rate:${email}`;

  async function sadd(k, v) {
    if (isFunction(client.sadd)) {return client.sadd(k, v);}
    if (isFunction(client.sAdd)) {return client.sAdd(k, v);}
    return null;
  }

  async function srem(k, v) {
    if (isFunction(client.srem)) {return client.srem(k, v);}
    if (isFunction(client.sRem)) {return client.sRem(k, v);}
    return null;
  }

  async function smembers(k) {
    if (isFunction(client.smembers)) {return client.smembers(k);}
    if (isFunction(client.sMembers)) {return client.sMembers(k);}
    return [];
  }

  async function mget(keys) {
    if (keys.length === 0) {return [];}
    if (isFunction(client.mget)) {return client.mget(...keys);}
    if (isFunction(client.mGet)) {return client.mGet(keys);}
    return Promise.all(keys.map(k => client.get(k)));
  }

  async function readRecord(id) {
    const raw = await client.get(rk(id));
    if (!raw) {return null;}
    try {
      return isString(raw) ? JSON.parse(raw) : raw;
    } catch {
      return null;
    }
  }

  return {
    async put(record) {
      if (!isObject(record) || !isString(record.id)) {
        throw invalidArgument('redisStore.put.record.id must be a string');
      }
      const now = Date.now();
      const ttlMs = Math.max(1, (record.expiresAt ?? now + 60_000) - now);
      // node-redis / ioredis both accept `set(k, v, 'PX', ttl)`.
      await client.set(rk(record.id), JSON.stringify(record), 'PX', ttlMs);
      if (isString(record.email)) {await sadd(ek(record.email), record.id);}
    },

    async getById(id) {
      return readRecord(id);
    },

    async consume(id) {
      const raw = await client.eval(CONSUME_SCRIPT, 1, rk(id), String(Date.now()));
      return Number(raw) === 1;
    },

    async listByEmail(email) {
      const ids = await smembers(ek(email));
      if (!ids || ids.length === 0) {return [];}
      const rows = await mget(ids.map(rk));
      const out = [];
      for (let i = 0; i < ids.length; i++) {
        const raw = rows[i];
        if (!raw) {
          // Dead index reference — prune.
          await srem(ek(email), ids[i]);
          continue;
        }
        try {
          out.push(isString(raw) ? JSON.parse(raw) : raw);
        } catch {
          // Skip corrupt row.
        }
      }
      return out;
    },

    async revokeByEmail(email) {
      const ids = await smembers(ek(email));
      if (!ids || ids.length === 0) {return 0;}
      let count = 0;
      for (const id of ids) {
        const ok = await this.consume(id);
        if (ok) {count += 1;}
      }
      return count;
    },

    async incrRate(email, ttlMs) {
      const raw = await client.eval(
        INCR_RATE_SCRIPT,
        1,
        rateKey(email),
        String(Math.max(1, Math.ceil(ttlMs))),
      );
      const arr = Array.isArray(raw) ? raw : [raw, ttlMs];
      const count = Number(arr[0]);
      const pttl = Number(arr[1]);
      return { count, expiresAt: Date.now() + (Number.isFinite(pttl) && pttl > 0 ? pttl : ttlMs) };
    },
  };
}
