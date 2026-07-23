/**
 * In-process memory store for magic links.
 *
 * Not cluster-safe: every worker has its own state. Use for dev,
 * single-node deployments, sticky-session behind an LB, and tests.
 * For multi-worker production use {@link redisStore} or ship your own
 * DB-backed store.
 *
 * Two indexes: `byId` (Map of id → record) is the primary lookup;
 * `byEmail` (Map of email → Set<id>) powers `listByEmail` and
 * `revokeByEmail`. Rate-limit counters delegate to the shared
 * IncrStore from `@exortek/shared/incr-store`.
 */

import { createMemoryRecordStore } from '@exortek/shared/record-store';
import { createMemoryIncrStore } from '@exortek/shared/incr-store';

/**
 * @returns {import('../index.js').MagicLinkStore & { _size: () => number, _stop: () => void }}
 */
export function memoryStore() {
  const store = createMemoryRecordStore({
    idField: 'id',
    indexField: 'email',
    copyStrategy: 'deep',
  });
  const incrStore = createMemoryIncrStore();

  return {
    put: record => store.put(record),
    getById: id => store.getById(id),
    listByEmail: email => store.listByIndex(email),

    async consume(id) {
      const existing = store.byId.get(id);
      if (!existing || existing.consumedAt) {
        return false;
      }
      existing.consumedAt = Date.now();
      return true;
    },

    async revokeByEmail(email) {
      const set = store.byIndex.get(email);
      if (!set) {
        return 0;
      }
      const now = Date.now();
      let count = 0;
      for (const id of set) {
        const record = store.byId.get(id);
        if (record && !record.consumedAt) {
          record.consumedAt = now;
          count += 1;
        }
      }
      return count;
    },

    async incrRate(email, ttlMs) {
      return incrStore.incr(email, ttlMs);
    },

    _size: () => store._size(),
    _stop: () => incrStore._stop(),
  };
}
