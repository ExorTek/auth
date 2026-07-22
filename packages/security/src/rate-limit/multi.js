import { isArray, isFunction } from '@exortek/shared/predicates';

import { SecurityError, ErrorCode } from '../internal/errors.js';

/**
 * Combine multiple limiters into one. A request is allowed only if **every**
 * inner limiter allows it; when any denies, the request is rejected with
 * the strictest `retryAfter` (max over deniers).
 *
 * Use for API-key style layered quotas — e.g. 100/min AND 1k/hour AND 10k/day.
 * Each inner limiter is a fully-formed limiter object; they can differ in
 * algorithm, window, or even backing store.
 *
 * @param {{ limiters: Array<import('./index.js').Limiter> }} config
 * @returns {import('./index.js').Limiter}
 */
export function multi(config) {
  if (!config || !isArray(config.limiters) || config.limiters.length === 0) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      'rateLimit.multi: config.limiters must be a non-empty array of limiter objects',
    );
  }
  for (const [i, limiter] of config.limiters.entries()) {
    if (!limiter || !isFunction(limiter.check)) {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        `rateLimit.multi: limiters[${i}] is missing a check() method`,
      );
    }
  }
  const limiters = config.limiters;

  return {
    async check(input) {
      // Run all checks concurrently — every inner limiter has already
      // recorded the hit against its own store, so partial failure on one
      // inner check would leave state drift. If atomicity across layers
      // matters to you, use a single limiter with a longer window.
      const results = await Promise.all(limiters.map(l => l.check(input)));

      let strictestRetryAfter = 0;
      let earliestReset = null;
      let minRemaining = Infinity;
      let anyDenied = false;

      for (const r of results) {
        if (!r.allowed) {
          anyDenied = true;
          if ((r.retryAfter ?? 0) > strictestRetryAfter) {
            strictestRetryAfter = r.retryAfter ?? 0;
          }
        }
        if (r.remaining < minRemaining) {
          minRemaining = r.remaining;
        }
        if (r.reset && (!earliestReset || r.reset < earliestReset)) {
          earliestReset = r.reset;
        }
      }

      if (anyDenied) {
        return {
          allowed: false,
          remaining: 0,
          reset: earliestReset,
          retryAfter: strictestRetryAfter || 1,
        };
      }
      return {
        allowed: true,
        remaining: minRemaining === Infinity ? 0 : minRemaining,
        reset: earliestReset,
        retryAfter: null,
      };
    },
  };
}
