/**
 * Redis-backed store for API keys.
 *
 * Layout:
 *
 *   <keyPrefix><id>            — JSON blob of the record (primary lookup)
 *   <keyPrefix>rev:<id>        — revocation tombstone (see below)
 *   <keyPrefix>u:<userId>      — SADD-set of the user's key ids
 *
 * Cluster-safe: state lives in Redis, so a key put on one worker is
 * immediately visible to every other. Works with any client exposing
 * `get / set / del / sadd / srem / smembers / mget` — verified against
 * `ioredis`, `node-redis@4+`, and `@upstash/redis`.
 *
 * There is no TTL on the record — API keys are meant to be long-lived
 * and their `expiresAt` field is authoritative.
 *
 * **Why tombstones:** `update()` is a read-modify-write (GET → SET), so
 * a concurrent `revoke()` on another worker could be overwritten by an
 * in-flight update carrying the pre-revoke copy — silently un-revoking
 * the key. Revocations are therefore written to a separate
 * `<keyPrefix>rev:<id>` key that no update path ever touches; `getById()`
 * and `listByUser()` overlay it onto the record. A revocation can never
 * be lost to a lost-update race.
 */

import { isString } from '@exortek/shared/predicates';
import { createRedisRecordStore } from '@exortek/shared/record-store';

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
  const keyPrefix = options.keyPrefix ?? 'apikey:';

  const store = createRedisRecordStore(client, {
    idField: 'id',
    indexField: 'userId',
    keyPrefix,
    tombstones: true,
    tombstonePrefix: 'rev:',
    indexPrefix: 'u:',
    applyTombstone(record, tomb) {
      record.revokedAt = record.revokedAt ?? Date.now();
      if (isString(tomb.reason) && record.revokedReason === undefined) {
        record.revokedReason = tomb.reason;
      }
      return record;
    },
    wrap: msg => {
      throw invalidArgument(msg);
    },
  });

  return {
    put: record => store.put(record),
    getById: id => store.getById(id),
    update: (id, patch) => store.update(id, patch),
    listByUser: userId => store.listByIndex(userId),

    async revoke(id, reason) {
      const existing = await store.readRecord(id);
      if (!existing || existing.revokedAt) {
        return false;
      }
      await store.writeTombstone(id, { reason: reason ?? null, at: Date.now() });
      existing.revokedAt = Date.now();
      if (isString(reason)) {
        existing.revokedReason = reason;
      }
      await store.writeRecord(existing);
      return true;
    },

    async revokeAllForUser(userId, reason) {
      const pairs = await store.fetchIndexRecords(userId);
      let count = 0;
      const writes = [];
      for (const [id, record] of pairs) {
        if (!record || record.revokedAt) {
          continue;
        }
        record.revokedAt = Date.now();
        if (isString(reason)) {
          record.revokedReason = reason;
        }
        writes.push(store.writeTombstone(id, { reason: reason ?? null, at: Date.now() }));
        writes.push(store.writeRecord(record));
        count += 1;
      }
      await Promise.all(writes);
      return count;
    },
  };
}
