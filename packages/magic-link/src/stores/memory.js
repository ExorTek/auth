/**
 * In-process memory store for magic links.
 *
 * Not cluster-safe: every worker has its own state. Use for dev,
 * single-node deployments, sticky-session behind an LB, and tests.
 * For multi-worker production use {@link redisStore} or ship your own
 * DB-backed store.
 *
 * Two indexes: `byId` (Map of id → record) is the primary lookup;
 * `byEmail` (Map of email → Set&lt;id&gt;) powers `listByEmail` and
 * `revokeByEmail`. A tiny separate map holds `incrRate` counters with
 * TTL, pruned lazily on read.
 */

import { isFunction, isString } from '@exortek/shared/predicates';

/**
 * @returns {import('../index.js').MagicLinkStore & { _size: () => number, _stop: () => void }}
 */
export function memoryStore() {
  /** @type {Map<string, import('../index.js').MagicLinkRecord>} */
  const byId = new Map();
  /** @type {Map<string, Set<string>>} */
  const byEmail = new Map();
  /** @type {Map<string, { count: number, expiresAt: number }>} */
  const rate = new Map();
  let sweeper = null;

  function scheduleSweeper() {
    if (sweeper) {return;}
    sweeper = setInterval(() => {
      const t = Date.now();
      for (const [k, v] of rate) {
        if (v.expiresAt <= t) {rate.delete(k);}
      }
    }, 60_000);
    if (isFunction(sweeper.unref)) {sweeper.unref();}
  }

  function indexEmail(email, id) {
    let set = byEmail.get(email);
    if (!set) {
      set = new Set();
      byEmail.set(email, set);
    }
    set.add(id);
  }

  return {
    async put(record) {
      // structuredClone gives us a deep copy so a caller mutating a
      // nested metadata object after put() cannot retroactively mutate
      // what we've stored. Same reason getById returns a clone.
      byId.set(record.id, structuredClone(record));
      if (isString(record.email)) {
        indexEmail(record.email, record.id);
      }
    },

    async getById(id) {
      const record = byId.get(id);
      return record ? structuredClone(record) : null;
    },

    async consume(id) {
      const existing = byId.get(id);
      if (!existing || existing.consumedAt) {return false;}
      existing.consumedAt = Date.now();
      return true;
    },

    async listByEmail(email) {
      const set = byEmail.get(email);
      if (!set) {
        return [];
      }
      const out = [];
      for (const id of set) {
        const record = byId.get(id);
        if (record) {
          out.push(structuredClone(record));
        }
      }
      return out;
    },

    async revokeByEmail(email) {
      const set = byEmail.get(email);
      if (!set) {return 0;}
      const now = Date.now();
      let count = 0;
      for (const id of set) {
        const record = byId.get(id);
        if (record && !record.consumedAt) {
          record.consumedAt = now;
          count += 1;
        }
      }
      return count;
    },

    async incrRate(email, ttlMs) {
      scheduleSweeper();
      const now = Date.now();
      const existing = rate.get(email);
      if (existing && existing.expiresAt > now) {
        existing.count += 1;
        // Refresh LRU position on activity.
        rate.delete(email);
        rate.set(email, existing);
        return { count: existing.count, expiresAt: existing.expiresAt };
      }
      const entry = { count: 1, expiresAt: now + ttlMs };
      rate.set(email, entry);
      return { count: 1, expiresAt: entry.expiresAt };
    },

    _size: () => byId.size,
    _stop: () => {
      if (sweeper) {
        clearInterval(sweeper);
        sweeper = null;
      }
    },
  };
}
