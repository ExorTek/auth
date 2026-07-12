/**
 * In-process memory store for rate-limit counters.
 *
 * Not cluster-safe: every worker/process/container has its own counters, so
 * the effective limit becomes `configured × replicas`. Use for dev, single-
 * node deploys, sticky-session behind an LB, tests, and background jobs.
 * For multi-process production, use the Redis adapter or a custom store.
 *
 * Eviction: true LRU (least-recently-used). Every `get` / `incr` / `set`
 * on an existing key re-inserts it so it becomes the newest entry;
 * `map.keys().next().value` is then the least-recently-touched key and is
 * dropped when `maxKeys` is exceeded. This matters for rate-limit: without
 * an access-refresh, an abuser hitting the same key repeatedly can be the
 * *oldest inserted* key and get their counter evicted (and reset) purely
 * by pushing the map over its cap — an unintended limiter bypass. `read`
 * is intentionally NOT refreshing, since it's an introspection call and
 * must not shift eviction order.
 *
 * LRU-via-Map-delete-then-set is textbook, popularized in the JS
 * community by projects like `toad-cache`
 * (https://github.com/kibertoad/toad-cache, MIT). No code is copied here;
 * we rely on the same ES2015 iteration-order guarantee.
 *
 * TTL: expired entries are removed lazily on read. A `setInterval` sweep
 * (unref'd so it never blocks process exit) also purges stale keys so
 * memory doesn't drift up for one-shot IPs.
 *
 * All operations are synchronous but returned as resolved Promises so the
 * store interface stays uniform with Redis / custom backends.
 *
 * @param {{ maxKeys?: number, sweepMs?: number }} [options]
 * @returns {import('../index.js').RateLimitStore & { _size: () => number, _stop: () => void }}
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
    // Map iteration order === insertion order + our access-time refresh:
    // the first key returned by keys() is the least-recently-touched one.
    const lruKey = map.keys().next().value;
    if (lruKey !== undefined) {
      map.delete(lruKey);
    }
  }

  // Non-mutating fetch. Used by `read` and by any internal path that must
  // not disturb LRU order.
  function peekFresh(key) {
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

  // Fetch + move to newest position. Used by `get` and `incr` — any activity
  // on a key marks it recently-used so eviction doesn't clip a hot caller.
  function touchFresh(key) {
    const entry = peekFresh(key);
    if (!entry) {
      return null;
    }
    map.delete(key);
    map.set(key, entry);
    return entry;
  }

  return {
    async get(key) {
      const entry = touchFresh(key);
      return entry ? { count: entry.count, expiresAt: entry.expiresAt } : null;
    },

    // Non-mutating read: does NOT refresh LRU position. Use for
    // introspection (e.g. "status" endpoints) where observing a counter
    // shouldn't keep it alive.
    async read(key) {
      const entry = peekFresh(key);
      return entry ? { count: entry.count, expiresAt: entry.expiresAt } : null;
    },

    async incr(key, ttlMs) {
      scheduleSweeper();
      const t = now();
      const existing = peekFresh(key);
      if (existing) {
        existing.count += 1;
        // Refresh LRU position on activity.
        map.delete(key);
        map.set(key, existing);
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
      // If the key exists, Map.set preserves its old insertion position.
      // Delete first so an overwrite moves it to newest — same LRU rule
      // as `incr`.
      if (map.has(key)) {
        map.delete(key);
      } else {
        evictIfFull();
      }
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
