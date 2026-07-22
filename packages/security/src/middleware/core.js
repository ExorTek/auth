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

// -------------------------------------------------------------------
// Framework-neutral runners.
//
// Each adapter (`express.js`, `fastify.js`)
// builds a small `AdapterContext` from its native request/response and
// hands it to these runners. Runners read the request via `ctx.method`
// / `ctx.getHeader` / `ctx.cookies` and write via `ctx.setHeader` /
// `ctx.setCookie` / `ctx.json` / `ctx.noContent`. Return values:
//
//   - `null | undefined` — the concern did not terminate the response;
//     the caller should continue the middleware chain.
//   - anything truthy — the concern terminated (deny / preflight); the
//     caller should stop the chain (Express: skip `next()`; Hono/Elysia:
//     return the response object the runner produced).
// -------------------------------------------------------------------

/**
 * @typedef {object} AdapterContext
 * @property {() => string} method  Uppercased HTTP method.
 * @property {(name: string) => string | undefined} getHeader
 *   Case-insensitive header lookup on the request.
 * @property {() => Record<string, string>} cookies
 *   Parsed request cookies.
 * @property {() => unknown} body
 *   Parsed request body (or undefined) — used by the CSRF form-field
 *   fallback when a token isn't in the header.
 * @property {(name: string, value: string) => void} setHeader
 *   Overwrite (or first-write) a response header.
 * @property {(name: string, value: string) => void} setHeaderIfAbsent
 *   Set a response header only if it isn't already present.
 * @property {(cookieName: string, cookieValue: string, cookieOptions: object) => void} setCookie
 *   Append a `Set-Cookie` header (or use the framework's native cookie
 *   API where available, e.g. Fastify's `reply.setCookie`).
 * @property {(status: number, body: unknown, extraHeaders?: Record<string, string>) => unknown} json
 *   Terminal response with a JSON body. Returns whatever the framework
 *   expects the middleware to return (Express: undefined, Hono: Response).
 * @property {(status: number, extraHeaders?: Record<string, string>) => unknown} noContent
 *   Terminal response with no body.
 * @property {() => string | undefined} ip
 *   Best-effort client IP (frameworks resolve this differently).
 * @property {() => unknown} rawReq
 *   Escape hatch for user callbacks (`keyGenerator`, `tokenFromRequest`)
 *   that expect the framework-native request object.
 * @property {() => unknown} rawRes
 *   Escape hatch for `onDenied`. `null` on frameworks without a distinct
 *   response object at this stage (Elysia).
 * @property {(key: string, value: unknown) => void} decorate
 *   Attach state to the request/context for later handlers
 *   (e.g. `req.csrfToken = () => ...`).
 */

async function _rawExtractCsrf(csrf, ctx) {
  if (typeof csrf.tokenFromRequest === 'function') {
    return csrf.tokenFromRequest(ctx.rawReq());
  }
  const h = ctx.getHeader(csrf.headerName);
  if (typeof h === 'string' && h.length > 0) {
    return h;
  }
  // Body may be sync (Express/Fastify already-parsed) or async (Hono
  // parseBody on demand). Await either shape uniformly.
  const body = await ctx.body();
  if (body && typeof body === 'object') {
    const v = /** @type {Record<string, unknown>} */ (body)[csrf.cookieName];
    if (typeof v === 'string' && v.length > 0) {
      return v;
    }
  }
  return undefined;
}

/**
 * Apply the response-header map. Returns nothing (never terminates).
 *
 * @param {ReadonlyArray<[string, string]>} entries  From `Object.entries(buildHeaders(...))`.
 * @param {AdapterContext} ctx
 */
export async function runHeaders(entries, ctx) {
  for (const [k, v] of entries) {
    ctx.setHeaderIfAbsent(k, v);
  }
}

/**
 * @param {ReturnType<typeof buildCorsCheck>} corsCheck
 * @param {AdapterContext} ctx
 * @param {ReadonlyArray<[string, string]> | null} [staticHeaders]
 *   Response-header map to fold into a preflight response so a preflight
 *   also carries the security headers the caller expects on every reply.
 * @returns {Promise<unknown>}   Response value (truthy → terminated) or null.
 */
export async function runCors(corsCheck, ctx, staticHeaders = null) {
  const verdict = corsCheck({
    method: ctx.method(),
    origin: ctx.getHeader('origin'),
    requestMethod: ctx.getHeader('access-control-request-method'),
    requestHeaders: ctx.getHeader('access-control-request-headers'),
  });
  const d = verdict && typeof verdict.then === 'function' ? await verdict : verdict;
  if (d.preflight) {
    const merged = { ...d.headers };
    if (staticHeaders) {
      for (const [k, v] of staticHeaders) {
        merged[k] = merged[k] ?? v;
      }
    }
    return ctx.noContent(d.status ?? 204, merged);
  }
  for (const [k, v] of Object.entries(d.headers)) {
    ctx.setHeader(k, v);
  }
  if (!d.allowed && ctx.getHeader('origin')) {
    return ctx.json(403, { error: 'ForbiddenOrigin' });
  }
  return null;
}

/**
 * @param {ReturnType<typeof normalizeRateLimit>} rateLimit
 * @param {AdapterContext} ctx
 * @returns {Promise<unknown>}
 */
export async function runRateLimit(rateLimit, ctx) {
  const key = rateLimit.keyGenerator ? rateLimit.keyGenerator(ctx.rawReq()) : ctx.ip();
  if (!key) {
    return null;
  }
  const result = await rateLimit.limiter.check({ key });
  const hn = rateLimit.headers;
  if (hn.retryAfter && result.retryAfter != null) {
    ctx.setHeader(hn.retryAfter, String(result.retryAfter));
  }
  if (hn.remaining) {
    ctx.setHeader(hn.remaining, String(result.remaining));
  }
  if (hn.reset && result.reset instanceof Date) {
    ctx.setHeader(hn.reset, String(Math.floor(result.reset.getTime() / 1000)));
  }
  if (result.allowed) {
    return null;
  }
  if (rateLimit.onDenied) {
    return rateLimit.onDenied(ctx.rawReq(), ctx.rawRes(), result);
  }
  return ctx.json(429, rateLimitDenialBody(result));
}

/**
 * @param {ReturnType<typeof normalizeCsrf>} csrf
 * @param {AdapterContext} ctx
 * @returns {Promise<unknown>}
 */
export async function runCsrf(csrf, ctx) {
  const cookies = ctx.cookies();
  const cookieToken = cookies[csrf.cookieName];

  let pending = null;
  const scheduleSetCookie = value => {
    ctx.setCookie(csrf.cookieName, value, csrf.cookieOptions);
  };
  ctx.decorate('csrfToken', () => {
    if (!pending) {
      pending = issueCsrfToken(csrf);
      scheduleSetCookie(pending);
    }
    return pending;
  });

  if (csrf.ignoreMethods.has(ctx.method().toUpperCase())) {
    if (!cookieToken) {
      const t = issueCsrfToken(csrf);
      scheduleSetCookie(t);
      pending = t;
    }
    return null;
  }

  const submitted = await _rawExtractCsrf(csrf, ctx);
  if (!cookieToken || !submitted || !verifyCsrfPair(csrf, cookieToken, submitted)) {
    return ctx.json(403, { error: 'CsrfInvalid' });
  }
  return null;
}
