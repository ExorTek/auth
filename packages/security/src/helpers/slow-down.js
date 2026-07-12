import { SecurityError, ErrorCode } from '../internal/errors.js';

/**
 * @typedef {object} SlowDownConfig
 * @property {import('../rate-limit/index.js').RateLimitStore} store
 * @property {string | number} window   Duration string ('1m', '30s') or ms.
 * @property {number} delayAfter        First `delayAfter` requests are free;
 *                                     subsequent ones get progressively delayed.
 * @property {number} delayMs           Base per-request delay after the free window.
 * @property {number} [maxDelayMs=20000]  Cap the per-request delay.
 * @property {'linear' | 'exponential'} [growth='linear']
 *   `linear`: delay = delayMs * excess.
 *   `exponential`: delay = delayMs * 2^(excess - 1) (capped by maxDelayMs).
 */

/**
 * Progressive-delay throttle — a "soft" rate limiter that never rejects but
 * slows abusers down. Sits nicely IN FRONT of a hard limiter: `slowDown`
 * catches naive scrapers cheaply, the limiter catches the persistent ones.
 *
 * The returned object exposes `.check({ key })` matching the rate-limit
 * contract, so `multi({ limiters: [slowDown(...), rateLimit.fixed(...)] })`
 * composes them.
 *
 * @param {SlowDownConfig} config
 * @returns {{ check: (input: { key: string }) => Promise<{
 *   allowed: boolean, remaining: number, reset: Date | null,
 *   retryAfter: number | null, delayMs: number,
 * }> }}
 */
export function slowDown(config) {
  if (!config || typeof config !== 'object') {
    throw new SecurityError(ErrorCode.INVALID_ARGUMENT, 'slowDown: config is required');
  }
  if (!config.store || typeof config.store.incr !== 'function') {
    throw new SecurityError(ErrorCode.INVALID_ARGUMENT, 'slowDown: store is required');
  }
  if (!Number.isInteger(config.delayAfter) || config.delayAfter < 0) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `slowDown: delayAfter must be a non-negative integer; got ${config.delayAfter}`,
    );
  }
  if (!Number.isFinite(config.delayMs) || config.delayMs < 0) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `slowDown: delayMs must be a non-negative number; got ${config.delayMs}`,
    );
  }

  const windowMs = parseWindow(config.window);
  const maxDelayMs = config.maxDelayMs ?? 20_000;
  const growth = config.growth ?? 'linear';

  return {
    async check(input) {
      if (!input || typeof input.key !== 'string' || input.key.length === 0) {
        throw new SecurityError(ErrorCode.INVALID_ARGUMENT, 'slowDown.check: input.key is required');
      }
      const bucketId = Math.floor(Date.now() / windowMs);
      const storeKey = `sd:${input.key}:${bucketId}`;
      const { count, expiresAt } = await config.store.incr(storeKey, windowMs);

      const excess = Math.max(0, count - config.delayAfter);
      let delayMs = 0;
      if (excess > 0) {
        delayMs =
          growth === 'exponential'
            ? Math.min(maxDelayMs, config.delayMs * 2 ** (excess - 1))
            : Math.min(maxDelayMs, config.delayMs * excess);
      }
      if (delayMs > 0) {
        await sleep(delayMs);
      }
      return {
        allowed: true,
        remaining: Math.max(0, config.delayAfter - count),
        reset: new Date(expiresAt),
        retryAfter: null,
        delayMs,
      };
    },
  };
}

function parseWindow(input) {
  if (typeof input === 'number') {
    if (!Number.isInteger(input) || input <= 0) {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        `slowDown.window must be a positive integer ms; got ${input}`,
      );
    }
    return input;
  }
  if (typeof input !== 'string') {
    throw new SecurityError(ErrorCode.INVALID_ARGUMENT, 'slowDown.window must be a duration string or ms number');
  }
  const m = /^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)\s*$/i.exec(input);
  if (!m) {
    throw new SecurityError(ErrorCode.INVALID_ARGUMENT, `slowDown.window invalid: '${input}'`);
  }
  const units = { ms: 1, s: 1000, m: 60000, h: 3600000, d: 86400000 };
  return Math.round(Number(m[1]) * units[m[2].toLowerCase()]);
}

function sleep(ms) {
  return new Promise(r => {
    const t = setTimeout(r, ms);
    if (typeof t.unref === 'function') {
      t.unref();
    }
  });
}
