import { parseDuration } from '../duration.js';
import { assertLimiterOptions, assertKey } from '../options.js';

/**
 * Fixed-window rate limiter.
 *
 * Every window boundary resets the counter to zero. Cheap (one INCR per
 * request) but permits burst at boundary edges — a caller can spend the
 * whole budget in the last second of one window and the whole budget in
 * the first second of the next. Prefer sliding for user-facing APIs; fixed
 * is fine for "cheap-and-lax" scenarios like debounce or dedup.
 *
 * @param {import('../index.js').WindowLimiterConfig} config
 * @returns {import('../index.js').Limiter}
 */
export function fixed(config) {
  assertLimiterOptions(config, 'fixed');
  const windowMs = parseDuration(config.window);
  const limit = config.requests;
  const store = config.store;

  return {
    async check(input) {
      assertKey(input);
      const { key } = input;
      const bucketId = Math.floor(Date.now() / windowMs);
      const storeKey = `f:${key}:${bucketId}`;
      const { count, expiresAt } = await store.incr(storeKey, windowMs);

      const remaining = Math.max(0, limit - count);
      const reset = new Date(expiresAt);

      if (count > limit) {
        return {
          allowed: false,
          remaining: 0,
          reset,
          retryAfter: Math.max(1, Math.ceil((expiresAt - Date.now()) / 1000)),
        };
      }

      return { allowed: true, remaining, reset, retryAfter: null };
    },
  };
}
