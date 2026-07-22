/**
 * In-process memory store for API keys.
 *
 * Not cluster-safe — every worker has its own state. Use for dev,
 * single-node deployments, and tests. For multi-worker production use
 * {@link redisStore} or bring your own DB-backed implementation of
 * `ApiKeyStore`.
 *
 * Backed by two Maps: one keyed by `id` (the primary lookup path),
 * one keyed by `userId` holding a `Set<id>` reverse index for
 * `listByUser` / `revokeAllForUser`. Both are pruned on write.
 */

import { isObject, isString, isUndefined } from '@exortek/shared/predicates';

import { invalidArgument } from '../internal/guards.js';

/**
 * @returns {import('../index.js').ApiKeyStore & { _size: () => number }}
 */
export function memoryStore() {
  /** @type {Map<string, import('../index.js').ApiKeyRecord>} */
  const byId = new Map();
  /** @type {Map<string, Set<string>>} */
  const byUser = new Map();

  function indexUser(uid, id) {
    if (!isString(uid)) {
      return;
    }
    let set = byUser.get(uid);
    if (!set) {
      set = new Set();
      byUser.set(uid, set);
    }
    set.add(id);
  }

  function unindexUser(uid, id) {
    if (!isString(uid)) {
      return;
    }
    const set = byUser.get(uid);
    if (!set) {
      return;
    }
    set.delete(id);
    if (set.size === 0) {
      byUser.delete(uid);
    }
  }

  return {
    async put(record) {
      if (!isObject(record) || !isString(record.id)) {
        throw invalidArgument('memoryStore.put.record.id must be a string');
      }
      byId.set(record.id, record);
      indexUser(record.userId, record.id);
    },

    async getById(id) {
      const record = byId.get(id);
      return record ? { ...record } : null;
    },

    async update(id, patch) {
      const existing = byId.get(id);
      if (!existing) {
        return null;
      }
      const oldUserId = existing.userId;
      const next = { ...existing, ...patch };
      byId.set(id, next);
      if (!isUndefined(patch.userId) && patch.userId !== oldUserId) {
        unindexUser(oldUserId, id);
        indexUser(next.userId, id);
      }
      return { ...next };
    },

    async revoke(id, reason) {
      const existing = byId.get(id);
      if (!existing || existing.revokedAt) {
        return false;
      }
      existing.revokedAt = Date.now();
      if (isString(reason)) {
        existing.revokedReason = reason;
      }
      return true;
    },

    async revokeAllForUser(userId, reason) {
      const set = byUser.get(userId);
      if (!set) {
        return 0;
      }
      const now = Date.now();
      let count = 0;
      for (const id of set) {
        const record = byId.get(id);
        if (record && !record.revokedAt) {
          record.revokedAt = now;
          if (isString(reason)) {
            record.revokedReason = reason;
          }
          count += 1;
        }
      }
      return count;
    },

    async listByUser(userId) {
      const set = byUser.get(userId);
      if (!set) {
        return [];
      }
      const out = [];
      for (const id of set) {
        const record = byId.get(id);
        if (record) {
          out.push({ ...record });
        }
      }
      return out;
    },

    _size: () => byId.size,
  };
}
