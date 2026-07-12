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
  if (!impl || typeof impl !== 'object') {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      'customStore(impl) requires an object with { get, incr, set, delete } methods',
    );
  }

  const required = ['get', 'incr', 'set', 'delete'];
  for (const name of required) {
    if (typeof impl[name] !== 'function') {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        `customStore: impl.${name} is required and must be a function`,
      );
    }
  }

  return {
    get: key => Promise.resolve(impl.get(key)),
    read: key => Promise.resolve(typeof impl.read === 'function' ? impl.read(key) : impl.get(key)),
    incr: (key, ttlMs) => Promise.resolve(impl.incr(key, ttlMs)),
    set: (key, count, ttlMs) => Promise.resolve(impl.set(key, count, ttlMs)),
    delete: key => Promise.resolve(impl.delete(key)),
    reset: key => Promise.resolve(typeof impl.reset === 'function' ? impl.reset(key) : impl.delete(key)),
  };
}
