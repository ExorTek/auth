/**
 * Replay guard — one place that decides whether a single-use identifier
 * (a DPoP proof `jti`, a client-assertion `jti`, a request-object `jti`) has
 * been seen before. Each server gets its own guard:
 *
 *   - with `stores.replay` — any IncrStore-shaped store (`incr(key, ttlMs)`
 *     → `{ count }` or a number, e.g. `@exortek/shared/incr-store` over
 *     Redis) — the check is shared by every node behind a load balancer;
 *   - without it, per-server in-memory two-bucket caches (single process).
 *
 * The first `incr` of a key returns 1; anything higher is a replay.
 */
import { isFunction, isNumber, isObject } from '@exortek/shared/predicates';

import { createReplayCache } from './replay-cache.js';

/**
 * @typedef {Object} ReplayStore
 * @property {(key: string, ttlMs: number) => Promise<{ count: number } | number> | { count: number } | number} incr
 *
 * @typedef {Object} ReplayGuard
 * @property {(namespace: string, id: string, ttlMs: number) => Promise<boolean>} seen
 *   record `id` under `namespace` for `ttlMs`; resolve true when it was already present
 */

/**
 * @param {unknown} value
 * @returns {value is ReplayStore}
 */
export function isReplayStore(value) {
  return isObject(value) && isFunction(/** @type {Record<string, unknown>} */ (value).incr);
}

/**
 * @param {ReplayStore} [store]
 * @returns {ReplayGuard}
 */
export function createReplayGuard(store) {
  if (store !== undefined) {
    return {
      async seen(namespace, id, ttlMs) {
        const res = await store.incr(`${namespace}:${id}`, ttlMs);
        const count = isNumber(res) ? res : res?.count;
        return !isNumber(count) || count > 1;
      },
    };
  }
  /** @type {Map<string, ReturnType<typeof createReplayCache>>} */
  const caches = new Map();
  return {
    async seen(namespace, id, ttlMs) {
      let cache = caches.get(namespace);
      if (!cache) {
        cache = createReplayCache(ttlMs);
        caches.set(namespace, cache);
      }
      return cache.seen(id);
    },
  };
}
