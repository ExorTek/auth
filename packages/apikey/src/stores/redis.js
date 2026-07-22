/**
 * Redis-backed store for API keys.
 *
 * Layout:
 *
 *   <keyPrefix><id>            — JSON blob of the record (primary lookup)
 *   <keyPrefix>u:<userId>      — SADD-set of the user's key ids
 *
 * Cluster-safe: state lives in Redis, so a key put on one worker is
 * immediately visible to every other. Works with any client exposing
 * `get / set / del / sadd / srem / smembers / mget` — verified against
 * `ioredis`, `node-redis@4+`, and `@upstash/redis`.
 *
 * There is no TTL on the record — API keys are meant to be long-lived
 * and their `expiresAt` field is authoritative. Revocation is a
 * flip-in-place on the record itself, not a tombstone, since
 * `verifyApiKey` re-reads the full record every time.
 */

import { assertRedisClient } from '@exortek/shared/redis-guard';
import { isFunction, isObject, isString } from '@exortek/shared/predicates';

import { invalidArgument } from '../internal/guards.js';

/**
 * @typedef {object} RedisStoreOptions
 * @property {string} [keyPrefix='apikey:']
 */

/**
 * @param {any} client
 * @param {RedisStoreOptions} [options]
 * @returns {import('../index.js').ApiKeyStore}
 */
export function redisStore(client, options = {}) {
  assertRedisClient(client, ['get', 'set', 'del'], msg => {
    throw invalidArgument(`redisStore.client: ${msg}`);
  });
  const keyPrefix = options.keyPrefix ?? 'apikey:';
  const rk = id => `${keyPrefix}${id}`;
  const uk = uid => `${keyPrefix}u:${uid}`;

  async function readRecord(id) {
    const raw = await client.get(rk(id));
    if (!raw) {
      return null;
    }
    try {
      return isString(raw) ? JSON.parse(raw) : raw;
    } catch {
      return null;
    }
  }

  async function writeRecord(record) {
    await client.set(rk(record.id), JSON.stringify(record));
  }

  async function sadd(uid, id) {
    if (isFunction(client.sadd)) {
      return client.sadd(uk(uid), id);
    }
    if (isFunction(client.sAdd)) {
      return client.sAdd(uk(uid), id);
    }
    return null;
  }

  async function srem(uid, id) {
    if (isFunction(client.srem)) {
      return client.srem(uk(uid), id);
    }
    if (isFunction(client.sRem)) {
      return client.sRem(uk(uid), id);
    }
    return null;
  }

  async function smembers(uid) {
    if (isFunction(client.smembers)) {
      return client.smembers(uk(uid));
    }
    if (isFunction(client.sMembers)) {
      return client.sMembers(uk(uid));
    }
    return [];
  }

  async function mget(keys) {
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
  }

  return {
    async put(record) {
      if (!isObject(record) || !isString(record.id)) {
        throw invalidArgument('redisStore.put.record.id must be a string');
      }
      await writeRecord(record);
      if (record.userId) {
        await sadd(record.userId, record.id);
      }
    },

    async getById(id) {
      return readRecord(id);
    },

    async update(id, patch) {
      const existing = await readRecord(id);
      if (!existing) {
        return null;
      }
      const oldUserId = existing.userId;
      const next = { ...existing, ...patch };
      await writeRecord(next);
      if (patch.userId !== undefined && patch.userId !== oldUserId) {
        if (oldUserId) {
          await srem(oldUserId, id);
        }
        if (next.userId) {
          await sadd(next.userId, id);
        }
      }
      return next;
    },

    async revoke(id, reason) {
      const existing = await readRecord(id);
      if (!existing || existing.revokedAt) {
        return false;
      }
      existing.revokedAt = Date.now();
      if (isString(reason)) {
        existing.revokedReason = reason;
      }
      await writeRecord(existing);
      return true;
    },

    async revokeAllForUser(userId, reason) {
      const ids = await smembers(userId);
      if (!ids || ids.length === 0) {
        return 0;
      }
      const rows = await mget(ids.map(rk));
      let count = 0;
      const writes = [];
      for (let i = 0; i < ids.length; i++) {
        const raw = rows[i];
        if (!raw) {
          continue;
        }
        let record;
        try {
          record = isString(raw) ? JSON.parse(raw) : raw;
        } catch {
          continue;
        }
        if (record.revokedAt) {
          continue;
        }
        record.revokedAt = Date.now();
        if (isString(reason)) {
          record.revokedReason = reason;
        }
        writes.push(writeRecord(record));
        count += 1;
      }
      await Promise.all(writes);
      return count;
    },

    async listByUser(userId) {
      const ids = await smembers(userId);
      if (!ids || ids.length === 0) {
        return [];
      }
      const rows = await mget(ids.map(rk));
      const out = [];
      for (let i = 0; i < ids.length; i++) {
        const raw = rows[i];
        if (!raw) {
          // Dead index reference — prune.
          await srem(userId, ids[i]);
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
  };
}
