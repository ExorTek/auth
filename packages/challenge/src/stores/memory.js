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
 * Eviction: true LRU (least-recently-used). Every `incr` on an existing
 * key re-inserts it so it becomes the newest entry;
 * `map.keys().next().value` is then the least-recently-touched key and
 * is dropped when `maxKeys` is exceeded. This matters for the
 * replay-guard tombstone: a repeated verify attempt refreshes the
 * `count > 1` entry so it stays authoritative until its TTL expires.
 * FIFO would let an idle tombstone age out prematurely and a third
 * replay attempt could see a fresh counter.
 *
 * Textbook pattern, popularised in the JS community by projects like
 * `toad-cache` (MIT); no code copied, only the same ES2015
 * iteration-order guarantee.
 *
 * Expired entries are pruned lazily on read, plus a `setInterval` sweep
 * (unref'd so it never blocks process exit). The `maxKeys` cap
 * protects against unbounded growth if the caller forgets to clean up.
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
        // Refresh LRU position on activity — the replay-guard tombstone
        // must stay warm until its TTL fires, or a third replay attempt
        // could see the entry evicted and get a fresh count.
        map.delete(key);
        map.set(key, existing);
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
