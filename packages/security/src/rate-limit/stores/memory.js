/**
 * In-process memory store for rate-limit counters.
 *
 * Not cluster-safe: every worker/process/container has its own counters, so
 * the effective limit becomes `configured × replicas`. Use for dev, single-
 * node deploys, sticky-session behind an LB, tests, and background jobs.
 * For multi-process production, use the Redis adapter or a custom store.
 *
 * Implementation notes:
 *   - Backed by a Map to preserve insertion order (used for LRU eviction).
 *   - Entries carry `{ count, expiresAt }`. On access, expired entries are
 *     lazily removed. A periodic sweeper also purges stale keys so the map
 *     doesn't grow unboundedly for one-shot IPs.
 *   - `maxKeys` caps memory: when exceeded, the oldest inserted entry is
 *     evicted (Map iteration order == insertion order).
 *   - All operations are synchronous but returned as resolved Promises so
 *     the store interface stays uniform with Redis/Mongo/custom.
 */
export function memoryStore(options = {}) {
  const maxKeys = options.maxKeys ?? 10_000;
  const sweepMs = options.sweepMs ?? 60_000;

  if (!Number.isInteger(maxKeys) || maxKeys < 1) {
    throw new TypeError(`memoryStore: maxKeys must be a positive integer; got ${maxKeys}`);
  }
  if (!Number.isInteger(sweepMs) || sweepMs < 1000) {
    throw new TypeError(`memoryStore: sweepMs must be an integer >= 1000; got ${sweepMs}`);
  }

  /** @type {Map<string, { count: number, expiresAt: number }>} */
  const map = new Map();
  let timer = null;

  const now = () => Date.now();

  function sweep() {
    const t = now();
    for (const [key, entry] of map) {
      if (entry.expiresAt <= t) {
        map.delete(key);
      }
    }
  }

  function scheduleSweeper() {
    if (timer) {
      return;
    }
    timer = setInterval(sweep, sweepMs);
    if (typeof timer.unref === 'function') {
      timer.unref();
    }
  }

  function evictIfFull() {
    if (map.size < maxKeys) {
      return;
    }
    // Map iteration order === insertion order. Drop the oldest key.
    const oldestKey = map.keys().next().value;
    if (oldestKey !== undefined) {
      map.delete(oldestKey);
    }
  }

  function readFresh(key) {
    const entry = map.get(key);
    if (!entry) {
      return null;
    }
    if (entry.expiresAt <= now()) {
      map.delete(key);
      return null;
    }
    return entry;
  }

  return {
    async get(key) {
      const entry = readFresh(key);
      return entry ? { count: entry.count, expiresAt: entry.expiresAt } : null;
    },

    async incr(key, ttlMs) {
      scheduleSweeper();
      const t = now();
      const existing = readFresh(key);
      if (existing) {
        existing.count += 1;
        return { count: existing.count, expiresAt: existing.expiresAt };
      }
      evictIfFull();
      const expiresAt = t + ttlMs;
      const entry = { count: 1, expiresAt };
      map.set(key, entry);
      return { count: 1, expiresAt };
    },

    async set(key, count, ttlMs) {
      scheduleSweeper();
      evictIfFull();
      const expiresAt = now() + ttlMs;
      map.set(key, { count, expiresAt });
    },

    async delete(key) {
      map.delete(key);
    },

    async reset(key) {
      map.delete(key);
    },

    // Test/inspection helpers, not part of the public interface.
    _size: () => map.size,
    _stop: () => {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    },
  };
}
