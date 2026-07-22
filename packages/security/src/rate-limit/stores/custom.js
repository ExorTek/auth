import { isFunction, isObject } from '@exortek/shared/predicates';

import { SecurityError, ErrorCode } from '../../internal/errors.js';

/**
 * Wrap a user-supplied store into the interface the rate-limit algorithms
 * expect. Validates that the required methods exist so misconfigurations
 * surface at startup, not at the first blocked request.
 *
 * Required methods (all may be async):
 *   - `get(key)`                  → { count, expiresAt } | null
 *   - `incr(key, ttlMs)`          → { count, expiresAt }   (atomic)
 *   - `set(key, count, ttlMs)`    → void
 *   - `delete(key)`               → void
 *
 * Optional:
 *   - `reset(key)`                → void (defaults to `delete`)
 *   - `decr(key)`                 → void — atomic decrement of an existing
 *     key. When provided, `sliding` uses it for race-free rollback of a
 *     rejected request's tentative increment.
 *   - `compareAndSet(key, expected, value, ttlMs)` → boolean — atomic CAS
 *     (`expected: null` = key must not exist). When provided,
 *     `tokenBucket` / `leakyBucket` become race-free under concurrency.
 *
 * Atomicity guarantee: `incr` must be atomic across concurrent callers. On
 * Redis, wrap `INCR + EXPIRE` in a Lua script or MULTI/EXEC. On Mongo, use
 * `findOneAndUpdate` with upsert. Non-atomic implementations race and let
 * requests bypass the limit under load.
 *
 * @param {Partial<import('../index.js').RateLimitStore>} impl
 * @returns {import('../index.js').RateLimitStore}
 */
export function customStore(impl) {
  if (!isObject(impl)) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      'customStore(impl) requires an object with { get, incr, set, delete } methods',
    );
  }

  const required = ['get', 'incr', 'set', 'delete'];
  for (const name of required) {
    if (!isFunction(impl[name])) {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        `customStore: impl.${name} is required and must be a function`,
      );
    }
  }

  const store = {
    get: key => Promise.resolve(impl.get(key)),
    read: key => Promise.resolve(isFunction(impl.read) ? impl.read(key) : impl.get(key)),
    incr: (key, ttlMs) => Promise.resolve(impl.incr(key, ttlMs)),
    set: (key, count, ttlMs) => Promise.resolve(impl.set(key, count, ttlMs)),
    delete: key => Promise.resolve(impl.delete(key)),
    reset: key => Promise.resolve(isFunction(impl.reset) ? impl.reset(key) : impl.delete(key)),
  };
  // Pass the atomic extras through ONLY when the impl provides them — the
  // algorithms feature-detect and fall back otherwise. Wrapping a missing
  // method in a stub would advertise atomicity the backend can't deliver.
  if (isFunction(impl.decr)) {
    store.decr = key => Promise.resolve(impl.decr(key));
  }
  if (isFunction(impl.compareAndSet)) {
    store.compareAndSet = (key, expected, value, ttlMs) =>
      Promise.resolve(impl.compareAndSet(key, expected, value, ttlMs)).then(Boolean);
  }
  return store;
}
