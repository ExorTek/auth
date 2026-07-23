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

import { isString } from '@exortek/shared/predicates';
import { createMemoryRecordStore } from '@exortek/shared/record-store';

/**
 * @returns {import('../index.js').ApiKeyStore & { _size: () => number }}
 */
export function memoryStore() {
  const store = createMemoryRecordStore({
    idField: 'id',
    indexField: 'userId',
    copyStrategy: 'shallow',
  });

  return {
    put: record => store.put(record),
    getById: id => store.getById(id),
    update: (id, patch) => store.update(id, patch),
    listByUser: userId => store.listByIndex(userId),

    async revoke(id, reason) {
      const existing = store.byId.get(id);
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
      const set = store.byIndex.get(userId);
      if (!set) {
        return 0;
      }
      const now = Date.now();
      let count = 0;
      for (const id of set) {
        const record = store.byId.get(id);
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

    _size: () => store._size(),
  };
}
