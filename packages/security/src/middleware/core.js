import { parseCookies as sharedParseCookies, serialiseCookie as sharedSerialiseCookie } from '@exortek/shared/cookie';

import { cors as buildCorsCheck } from '../cors/index.js';
import { headers as buildHeaders } from '../headers/index.js';
import { generate as csrfGenerate, verify as csrfVerify } from '../csrf/index.js';
import { SecurityError, ErrorCode } from '../internal/errors.js';
import { invalidArgument } from '../internal/guards.js';

/**
 * @typedef {object} CsrfMiddlewareOptions
 * @property {string | Buffer} secret       Minimum 32 bytes of entropy.
 * @property {string} [cookieName='__Host-csrf']
 * @property {string} [headerName='x-csrf-token']
 * @property {string[]} [ignoreMethods=['GET','HEAD','OPTIONS']]
 * @property {object} [cookieOptions]       Overrides for the Set-Cookie flags.
 * @property {(req: unknown) => string | undefined} [tokenFromRequest]
 */

/**
 * @typedef {object} RateLimitMiddlewareOptions
 * @property {{ check: Function }} limiter
 * @property {(req: unknown) => string | undefined} [keyGenerator]
 * @property {(req: unknown, res: unknown, result: object) => unknown} [onDenied]
 * @property {boolean} [trustProxy=false]
 *   Whether the default key generator may read the client IP from the
 *   `X-Forwarded-For` header. That header is client-controlled, so trusting
 *   it without a proxy in front lets an attacker rotate it to mint unlimited
 *   rate-limit buckets (limit bypass) or spoof another user's IP. Leave
 *   `false` unless your app sits behind a proxy/CDN that overwrites XFF.
 *   Ignored when `keyGenerator` is supplied. (Express adapter uses `req.ip`,
 *   which already honours the framework's own `trust proxy` setting.)
 */

/**
 * @typedef {object} SecurityMiddlewareOptions
 * @property {import('../headers/index.js').HeadersOptions | boolean} [headers]
 * @property {import('../cors/index.js').CorsOptions | false} [cors]
 * @property {CsrfMiddlewareOptions | false} [csrf]
 * @property {RateLimitMiddlewareOptions | false} [rateLimit]
 */

const CSRF_DEFAULT_COOKIE_FLAGS = Object.freeze({
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  path: '/',
});

function assertCsrfSecret(secret) {
  if (typeof secret !== 'string' && !Buffer.isBuffer(secret)) {
    throw invalidArgument('csrf.secret must be a string or Buffer');
  }
  const len = Buffer.isBuffer(secret) ? secret.length : Buffer.byteLength(secret, 'utf8');
  if (len < 32) {
    throw invalidArgument(
      `csrf.secret must be at least 32 bytes; got ${len}. Generate with \`crypto.randomBytes(32).toString('hex')\`.`,
    );
  }
}

/**
 * Normalize the CSRF options into a fully-populated config with defaults.
 */
export function normalizeCsrf(options) {
  assertCsrfSecret(options.secret);
  return {
    secret: options.secret,
    cookieName: options.cookieName ?? '__Host-csrf',
    headerName: (options.headerName ?? 'x-csrf-token').toLowerCase(),
    ignoreMethods: new Set((options.ignoreMethods ?? ['GET', 'HEAD', 'OPTIONS']).map(m => m.toUpperCase())),
    cookieOptions: { ...CSRF_DEFAULT_COOKIE_FLAGS, ...(options.cookieOptions ?? {}) },
    tokenFromRequest: options.tokenFromRequest,
  };
}

/**
 * Normalize the rate-limit options. `limiter` is required.
 */
export function normalizeRateLimit(options) {
  if (!options.limiter || typeof options.limiter.check !== 'function') {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      'rateLimit.limiter must be a compiled limiter (e.g. rateLimit.sliding({...})).',
    );
  }
  return {
    limiter: options.limiter,
    keyGenerator: options.keyGenerator,
    onDenied: options.onDenied,
    trustProxy: options.trustProxy === true,
    headers: normalizeRateLimitHeaders(options.headers ?? 'legacy'),
  };
}

/**
 * @typedef {object} RateLimitHeaderNames
 * @property {string | false} [remaining]  Header name for remaining budget.
 * @property {string | false} [reset]      Header name for reset timestamp.
 * @property {string | false} [retryAfter] Header name for the deny hint.
 */

const HEADER_PRESETS = Object.freeze({
  // Historical widely-deployed names — matches express-rate-limit / helmet
  // demos. Default for backward compatibility.
  legacy: { remaining: 'X-RateLimit-Remaining', reset: 'X-RateLimit-Reset', retryAfter: 'Retry-After' },
  // draft-ietf-httpapi-ratelimit-headers (RFC 9331 draft) — the future.
  draft: { remaining: 'RateLimit-Remaining', reset: 'RateLimit-Reset', retryAfter: 'Retry-After' },
});

/**
 * Normalize the `headers` option on rate-limit middleware into a
 * `{ remaining, reset, retryAfter }` object with either string names or
 * `false` for "skip this one". Accepts:
 *   - `false`                 — emit nothing (privacy / info-leak posture)
 *   - `'legacy'` (default)    — `X-RateLimit-*` + `Retry-After`
 *   - `'draft'`               — `RateLimit-*` per RFC 9331 draft
 *   - object                  — override individual names / disable individually
 */
function normalizeRateLimitHeaders(input) {
  if (input === false) {
    return { remaining: false, reset: false, retryAfter: false };
  }
  if (typeof input === 'string') {
    const preset = HEADER_PRESETS[input];
    if (!preset) {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        `rateLimit.headers preset must be 'legacy' or 'draft'; got '${input}'`,
      );
    }
    return { ...preset };
  }
  if (typeof input === 'object' && input !== null) {
    // Start from the legacy preset and let user-supplied fields override.
    // `false` on any field disables just that header.
    return {
      remaining: input.remaining ?? HEADER_PRESETS.legacy.remaining,
      reset: input.reset ?? HEADER_PRESETS.legacy.reset,
      retryAfter: input.retryAfter ?? HEADER_PRESETS.legacy.retryAfter,
    };
  }
  throw new SecurityError(
    ErrorCode.INVALID_ARGUMENT,
    "rateLimit.headers must be false, 'legacy', 'draft', or an object mapping",
  );
}

/**
 * Normalize the umbrella `securityMiddleware()` options. Returns per-concern
 * configs (or `null` when disabled) that adapters compose.
 *
 * @param {SecurityMiddlewareOptions} options
 */
export function normalizeUmbrella(options = {}) {
  const responseHeaders =
    options.headers === false
      ? null
      : buildHeaders(options.headers === true || options.headers === undefined ? {} : options.headers);

  const corsCheck = options.cors === undefined || options.cors === false ? null : buildCorsCheck(options.cors);

  const csrf = options.csrf === undefined || options.csrf === false ? null : normalizeCsrf(options.csrf);

  const rateLimit =
    options.rateLimit === undefined || options.rateLimit === false ? null : normalizeRateLimit(options.rateLimit);

  return { responseHeaders, corsCheck, csrf, rateLimit };
}

// Small helpers used by adapters below.

export function extractCsrfToken(csrfConfig, req) {
  if (typeof csrfConfig.tokenFromRequest === 'function') {
    return csrfConfig.tokenFromRequest(req);
  }
  const h = req.headers?.[csrfConfig.headerName];
  if (typeof h === 'string' && h.length > 0) {
    return h;
  }
  const body = req.body;
  if (body && typeof body === 'object') {
    const v = body[csrfConfig.cookieName];
    if (typeof v === 'string' && v.length > 0) {
      return v;
    }
  }
  return undefined;
}

export function issueCsrfToken(csrfConfig) {
  return csrfGenerate(csrfConfig.secret);
}

export function verifyCsrfPair(csrfConfig, cookie, headerValue) {
  return csrfVerify(cookie, headerValue, csrfConfig.secret);
}

export function serializeCookie(name, value, opts) {
  try {
    return sharedSerialiseCookie(name, value, opts);
  } catch (err) {
    throw invalidArgument(err instanceof Error ? err.message : String(err), { cause: err });
  }
}

export const parseCookies = sharedParseCookies;

export function rateLimitDenialBody(result) {
  return {
    error: 'RateLimited',
    message: `Rate limit exceeded. Retry in ${result.retryAfter ?? 1}s.`,
    retryAfter: result.retryAfter ?? 1,
  };
}

// Also re-export the raw builders so adapters don't reach around us.
export { buildCorsCheck, buildHeaders };
