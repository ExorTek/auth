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

import { createMemoryIncrStore } from '@exortek/shared/incr-store';

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
  return createMemoryIncrStore(options, msg => {
    throw invalidArgument(msg);
  });
}
