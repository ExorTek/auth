/**
 * In-process blacklist / refresh-token store with configurable GC.
 *
 * Uses a `Map<string, StoreRecord>` for O(1) lookups. Expiry is always
 * enforced on `has` / `get` — expired records are never returned. The
 * GC strategy only controls how the underlying map reclaims memory:
 *
 *   - `interval` (default) — a periodic sweep drops expired entries;
 *     safe under high churn but wakes the event loop at fixed cadence.
 *   - `lazy` — no sweep; expired entries linger in the map until they
 *     are queried. Zero background CPU.
 *   - `lru` — like `interval` but with a `maxSize` cap; the
 *     least-recently-added record is evicted when the cap is reached.
 *     WARNING: never use `lru` as a revocation blacklist — eviction
 *     silently un-revokes tokens whose entry got dropped for capacity.
 */

import { JwtError, ErrorCode } from './errors.js';
import { parseDuration } from './duration.js';

/**
 * @typedef {Object} StoreRecord
 * @property {number} expiresAt
 * @property {Record<string, unknown>} [metadata]
 *
 * @typedef {Object} Store
 * @property {(key: string, expiresAt: number, metadata?: Record<string, unknown>) => Promise<void>} add
 * @property {(key: string) => Promise<boolean>} has
 * @property {(key: string) => Promise<StoreRecord | null>} get
 * @property {(key: string) => Promise<void>} delete
 * @property {(filter: Record<string, unknown>) => Promise<number>} deleteAll
 * @property {() => number} size
 * @property {() => void} _stop
 *
 * @typedef {Object} MemoryConfig
 * @property {number} [maxSize]
 * @property {{ strategy?: 'interval' | 'lazy' | 'lru', interval?: string | number, maxSize?: number }} [gc]
 */

/**
 * @param {MemoryConfig} [options]
 * @returns {Store}
 */
export function createMemoryStore(options) {
  const opts = options || {};
  const gc = opts.gc || {};
  const strategy = gc.strategy || 'interval';
  const maxSize = gc.maxSize ?? opts.maxSize ?? Infinity;
  const intervalMs =
    strategy === 'interval' || strategy === 'lru' ? Math.max(1000, parseDuration(gc.interval ?? '5m') * 1000) : 0;

  /** @type {Map<string, StoreRecord>} */
  const map = new Map();
  /** @type {NodeJS.Timeout | null} */
  let timer = null;

  const now = () => Math.floor(Date.now() / 1000);

  const expiredSweep = () => {
    const t = now();
    for (const [k, v] of map) {
      if (v.expiresAt <= t) {
        map.delete(k);
      }
    }
  };

  const enforceCap = () => {
    if (map.size <= maxSize) {
      return;
    }
    // Drop insertion-order oldest until under cap. Map preserves
    // insertion order (ES2015+).
    while (map.size > maxSize) {
      const oldest = map.keys().next().value;
      if (oldest === undefined) {
        break;
      }
      map.delete(oldest);
    }
  };

  if (intervalMs > 0) {
    timer = setInterval(() => {
      expiredSweep();
      enforceCap();
    }, intervalMs);
    if (typeof timer.unref === 'function') {
      timer.unref();
    }
  }

  const matches = (record, filter) => {
    const meta = record.metadata;
    if (!meta) {
      return false;
    }
    for (const [k, v] of Object.entries(filter)) {
      if (meta[k] !== v) {
        return false;
      }
    }
    return true;
  };

  return {
    async add(key, expiresAt, metadata) {
      if (typeof key !== 'string' || key.length === 0) {
        throw new JwtError(ErrorCode.STORE_ERROR, 'memory-store.add: key must be a non-empty string');
      }
      if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt)) {
        throw new JwtError(ErrorCode.STORE_ERROR, 'memory-store.add: expiresAt must be a finite NumericDate');
      }
      map.set(key, { expiresAt, ...(metadata ? { metadata } : {}) });
      if (strategy === 'lru') {
        enforceCap();
      }
    },
    async has(key) {
      const record = map.get(key);
      if (!record) {
        return false;
      }
      if (record.expiresAt <= now()) {
        map.delete(key);
        return false;
      }
      return true;
    },
    async get(key) {
      const record = map.get(key);
      if (!record) {
        return null;
      }
      if (record.expiresAt <= now()) {
        map.delete(key);
        return null;
      }
      return record;
    },
    async delete(key) {
      map.delete(key);
    },
    async deleteAll(filter) {
      if (filter == null || typeof filter !== 'object') {
        throw new JwtError(
          ErrorCode.STORE_ERROR,
          'memory-store.deleteAll: filter must be an object of metadata key/value pairs',
        );
      }
      let count = 0;
      for (const [k, record] of map) {
        if (matches(record, filter)) {
          map.delete(k);
          count++;
        }
      }
      return count;
    },
    size() {
      return map.size;
    },
    _stop() {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    },
  };
}
