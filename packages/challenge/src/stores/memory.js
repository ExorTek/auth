/**
 * In-process memory store for challenge single-use enforcement.
 *
 * Not cluster-safe: every worker has its own state, so a token accepted
 * on one worker could still be replayed on another. Use for dev,
 * single-node deploys, sticky-session behind an LB, and tests. For
 * multi-worker production, use {@link redisStore} or pass any object
 * exposing `incr(key, ttlMs) → { count }` (e.g.
 * `@exortek/security`'s rate-limit stores).
 *
 * Expired entries are pruned lazily on read, plus a `setInterval` sweep
 * (unref'd so it never blocks process exit). A `maxKeys` cap protects
 * against unbounded growth if the caller forgets to clean up — the
 * oldest-inserted entry is dropped when the cap is exceeded.
 */

import { isFunction, isInteger, isUndefined } from '@exortek/shared/predicates';

import { invalidArgument } from '../internal/guards.js';

/**
 * @typedef {object} MemoryStoreOptions
 * @property {number} [maxKeys=10000]   Hard cap; oldest entry dropped when exceeded.
 * @property {number} [sweepMs=60000]   Interval for the background TTL sweep.
 */

/**
 * @param {MemoryStoreOptions} [options]
 * @returns {import('./index.js').IncrStore & { _size: () => number, _stop: () => void }}
 */
export function memoryStore(options = {}) {
  const maxKeys = options.maxKeys ?? 10_000;
  const sweepMs = options.sweepMs ?? 60_000;

  if (!isInteger(maxKeys) || maxKeys < 1) {
    throw invalidArgument(`memoryStore.options.maxKeys must be a positive integer; got ${maxKeys}`);
  }
  if (!isInteger(sweepMs) || sweepMs < 1000) {
    throw invalidArgument(`memoryStore.options.sweepMs must be an integer >= 1000; got ${sweepMs}`);
  }

  /** @type {Map<string, { count: number, expiresAt: number }>} */
  const map = new Map();
  let timer = null;

  function peekFresh(key) {
    const entry = map.get(key);
    if (!entry) {
      return null;
    }
    if (entry.expiresAt <= Date.now()) {
      map.delete(key);
      return null;
    }
    return entry;
  }

  function sweep() {
    const t = Date.now();
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
    if (isFunction(timer.unref)) {
      timer.unref();
    }
  }

  function evictIfFull() {
    if (map.size < maxKeys) {
      return;
    }
    const oldest = map.keys().next().value;
    if (!isUndefined(oldest)) {
      map.delete(oldest);
    }
  }

  return {
    async incr(key, ttlMs) {
      scheduleSweeper();
      const existing = peekFresh(key);
      if (existing) {
        existing.count += 1;
        return { count: existing.count, expiresAt: existing.expiresAt };
      }
      evictIfFull();
      const expiresAt = Date.now() + ttlMs;
      map.set(key, { count: 1, expiresAt });
      return { count: 1, expiresAt };
    },

    _size: () => map.size,
    _stop: () => {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    },
  };
}
