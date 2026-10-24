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
import { isFunction } from '@exortek/shared/predicates';

/**
 * Records are swept once they expire, and the store holds at most
 * `maxRecords` (oldest dropped first) — a link that is never clicked must
 * not stay in memory forever.
 *
 * @param {{ maxRecords?: number, sweepMs?: number }} [options]
 * @returns {import('../index.js').MagicLinkStore & { _size: () => number, _stop: () => void }}
 */
export function memoryStore(options = {}) {
  const { maxRecords = 100_000, sweepMs = 60_000 } = options;
  const store = createMemoryRecordStore({
    idField: 'id',
    indexField: 'email',
    copyStrategy: 'deep',
  });
  const incrStore = createMemoryIncrStore();

  function drop(id) {
    const record = store.byId.get(id);
    store.byId.delete(id);
    const set = record ? store.byIndex.get(record.email) : undefined;
    set?.delete(id);
    if (set?.size === 0) {
      store.byIndex.delete(record.email);
    }
  }

  const timer = setInterval(() => {
    const now = Date.now();
    for (const [id, record] of store.byId) {
      if (record.expiresAt <= now) {
        drop(id);
      }
    }
  }, sweepMs);
  if (isFunction(timer.unref)) {
    timer.unref();
  }

  return {
    async put(record) {
      if (!store.byId.has(record.id) && store.byId.size >= maxRecords) {
        // Map iteration order is insertion order: the first key is the oldest.
        drop(store.byId.keys().next().value);
      }
      await store.put(record);
    },
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
    _stop: () => {
      clearInterval(timer);
      incrStore._stop();
    },
  };
}
