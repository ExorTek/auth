import { isFunction } from '@exortek/shared/predicates';

import { parseDuration } from '../duration.js';
import { assertLimiterOptions, assertKey } from '../options.js';

/**
 * Interpolated sliding-window rate limiter.
 *
 * Approximates a true sliding window using two fixed buckets — the current
 * window's counter plus a weighted slice of the previous window's counter,
 * where the weight is the fraction of the previous window still overlapping
 * with "now". This costs the same as fixed (~1 write) but eliminates the
 * boundary burst that plagues fixed windows.
 *
 * Accuracy: ~1% off ground truth in the worst case (Cloudflare / Kong /
 * Envoy all ship this variant as their default). For strict per-user API
 * quotas this is normally within a few requests of the true count.
 *
 * @param {import('../index.js').WindowLimiterConfig} config
 * @returns {import('../index.js').Limiter}
 */
export function sliding(config) {
  assertLimiterOptions(config, 'sliding');
  const windowMs = parseDuration(config.window);
  const limit = config.requests;
  const store = config.store;

  return {
    async check(input) {
      assertKey(input);
      const { key } = input;
      const now = Date.now();
      const currentBucket = Math.floor(now / windowMs);
      const previousBucket = currentBucket - 1;
      const positionInWindow = (now % windowMs) / windowMs; // 0..1

      const currentKey = `s:${key}:${currentBucket}`;
      const previousKey = `s:${key}:${previousBucket}`;

      // Tentatively count the new request in the current bucket. If it
      // exceeds the interpolated limit, roll back so the counter doesn't
      // drift on rejection-heavy traffic.
      const current = await store.incr(currentKey, windowMs * 2);
      const previous = await store.get(previousKey);
      // `store.get` preserves the raw wire type — sliding stores its
      // count via `incr` (integer), but the Redis adapter returns it
      // as a string on the wire. Coerce explicitly for the arithmetic
      // below.
      const previousCount = previous ? Number(previous.count) || 0 : 0;

      const interpolated = current.count + previousCount * (1 - positionInWindow);
      const reset = new Date(now + Math.ceil(windowMs * (1 - positionInWindow)));

      if (interpolated > limit) {
        // Roll back the tentative increment so future checks report the
        // correct remaining count. Prefer the store's atomic `decr` — the
        // read-modify-write `set` fallback can race a concurrent `incr`
        // and overwrite it, silently under-counting the window.
        if (isFunction(store.decr)) {
          await store.decr(currentKey);
        } else {
          await store.set(currentKey, current.count - 1, Math.max(1, current.expiresAt - now));
        }
        return {
          allowed: false,
          remaining: 0,
          reset,
          retryAfter: Math.max(1, Math.ceil(((interpolated - limit) / limit) * (windowMs / 1000))),
        };
      }

      return {
        allowed: true,
        remaining: Math.max(0, Math.floor(limit - interpolated)),
        reset,
        retryAfter: null,
      };
    },
  };
}
