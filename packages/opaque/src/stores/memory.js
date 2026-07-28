/**
 * In-process memory store for opaque tokens.
 *
 * Not cluster-safe: every worker has its own state. Use for dev,
 * single-node deployments, and tests. For multi-worker production use
 * {@link redisStore} or bring your own implementation of the
 * `OpaqueStore` interface (`set` / `get` / `delete`).
 *
 * A plain `Map<hash, { value, expiresAt }>`. Expired entries are
 * pruned lazily on `get`, plus a background `setInterval` sweep
 * (unref'd so it never blocks process exit) for entries nobody reads
 * again before they expire.
 */

import { parseDuration } from '@exortek/shared/duration';

/**
 * @typedef {object} MemoryStoreOptions
 * @property {number} [sweepMs=60000]  Interval for the background TTL sweep.
 */

/**
 * @param {MemoryStoreOptions} [options]
 * @returns {import('../index.js').OpaqueStore & { _size: () => number, _stop: () => void }}
 */
export function memoryStore(options = {}) {
  const { sweepMs = 60000 } = options;

  /** @type {Map<string, { value: Record<string, unknown>, expiresAt: number | null }>} */
  const map = new Map();

  function isExpired(entry) {
    return entry.expiresAt !== null && entry.expiresAt <= Date.now();
  }

  const timer = setInterval(() => {
    for (const [key, entry] of map) {
      if (isExpired(entry)) {
        map.delete(key);
      }
    }
  }, sweepMs);
  if (typeof timer.unref === 'function') {
    timer.unref();
  }

  return {
    async set(key, value, opts = {}) {
      const expiresAt = opts.expiresIn !== undefined ? Date.now() + parseDuration(opts.expiresIn) : null;
      map.set(key, { value, expiresAt });
    },

    async get(key) {
      const entry = map.get(key);
      if (!entry) {
        return null;
      }
      if (isExpired(entry)) {
        map.delete(key);
        return null;
      }
      return entry.value;
    },

    async delete(key) {
      return map.delete(key);
    },

    _size: () => map.size,
    _stop: () => clearInterval(timer),
  };
}
