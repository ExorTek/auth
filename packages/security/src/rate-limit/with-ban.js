import { SecurityError, ErrorCode } from '../internal/errors.js';
import { parseDuration } from './duration.js';

/**
 * Wrap any limiter with a violation-count ban policy. When a caller
 * triggers `threshold` denials within `trackingWindow`, we bump them to
 * a hard ban for `banDuration` — subsequent `.check()` calls short-circuit
 * to denied without touching the base limiter.
 *
 * Sits nicely on top of a stricter-than-you-need limiter: the base
 * limiter catches ordinary abuse, `withBan` catches persistent abuse
 * cheaply (a single `store.get` per request while in the ban window,
 * no HMAC / no algorithm work).
 *
 *   const limiter = rateLimit.withBan(
 *     rateLimit.sliding({ requests: 20, window: '1m', store }),
 *     { store, threshold: 5, banDuration: '1h' },
 *   )
 *
 * State is written with the prefixes `bs:v:<key>` (violation counter,
 * TTL = trackingWindow) and `bs:b:<key>` (ban marker, TTL = banDuration).
 * You can share the base limiter's store or provide a dedicated one.
 *
 * @param {import('./index.js').Limiter} limiter
 * @param {{
 *   store: import('./index.js').RateLimitStore,
 *   threshold: number,
 *   banDuration: string | number,
 *   trackingWindow?: string | number,
 * }} options
 * @returns {import('./index.js').Limiter}
 */
export function withBan(limiter, options) {
  if (!limiter || typeof limiter.check !== 'function') {
    throw new SecurityError(ErrorCode.INVALID_ARGUMENT, 'rateLimit.withBan: limiter must expose a .check() method');
  }
  if (!options || !options.store || typeof options.store.get !== 'function') {
    throw new SecurityError(ErrorCode.INVALID_ARGUMENT, 'rateLimit.withBan: options.store must be a compatible store');
  }
  if (!Number.isInteger(options.threshold) || options.threshold < 1) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `rateLimit.withBan: threshold must be a positive integer; got ${options.threshold}`,
    );
  }
  const banMs = parseDuration(options.banDuration, 'banDuration');
  const trackingMs = parseDuration(options.trackingWindow ?? options.banDuration, 'trackingWindow');
  const store = options.store;

  return {
    async check(input) {
      if (!input || typeof input.key !== 'string' || input.key.length === 0) {
        throw new SecurityError(ErrorCode.INVALID_ARGUMENT, 'rateLimit.withBan.check: input.key is required');
      }
      const banKey = `bs:b:${input.key}`;
      const banned = await store.get(banKey);
      if (banned && banned.expiresAt > Date.now()) {
        const retryAfter = Math.max(1, Math.ceil((banned.expiresAt - Date.now()) / 1000));
        return {
          allowed: false,
          remaining: 0,
          reset: new Date(banned.expiresAt),
          retryAfter,
        };
      }

      const result = await limiter.check(input);
      if (!result.allowed) {
        const { count } = await store.incr(`bs:v:${input.key}`, trackingMs);
        if (count >= options.threshold) {
          await store.set(banKey, 1, banMs);
        }
      }
      return result;
    },
  };
}
