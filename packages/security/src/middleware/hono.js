import {
  normalizeUmbrella,
  normalizeCsrf,
  normalizeRateLimit,
  parseCookies,
  serializeCookie,
  buildCorsCheck,
  buildHeaders,
  runHeaders,
  runCors,
  runRateLimit,
  runCsrf,
} from './core.js';

/*
 * Hono adapter. Each concern is exposed as its own middleware factory:
 *   headersMiddleware, corsMiddleware, csrfMiddleware, rateLimitMiddleware,
 * plus the bundle:
 *   securityMiddleware.
 *
 * Hono runs on the Web-standard Request/Response contract, so all of these
 * work unchanged on Node, Bun, Cloudflare Workers, Deno, and Vercel Edge.
 *
 * IP resolution: on non-Node runtimes there is no `req.ip`. The default
 * key generator only reads `X-Forwarded-For` when `trustProxy: true` is
 * set — that header is client-controlled, so trusting it without a proxy
 * in front lets an attacker rotate it to bypass the limit. Otherwise pass
 * an explicit `keyGenerator` reading your platform's trusted IP header,
 * e.g. `keyGenerator: (c) => c.req.header('cf-connecting-ip')` on
 * Cloudflare.
 */

function ipFromCtx(c, trustProxy) {
  if (!trustProxy) return undefined;
  const xff = c.req.header('x-forwarded-for');
  if (typeof xff === 'string' && xff.length) {
    return xff.split(',')[0].trim();
  }
  return undefined;
}

/**
 * Build the framework-neutral `AdapterContext` from Hono's `Context`.
 * Runners in `core.js` do the actual work.
 *
 * Hono's response model is "return a Response from the handler". Every
 * terminal method on the returned context (`json`, `noContent`) hands
 * back a Response the middleware wrapper propagates.
 *
 * @param {any} c
 * @param {{ trustProxy?: boolean }} [flags]
 * @returns {import('./core.js').AdapterContext}
 */
function makeHonoContext(c, flags = {}) {
  return {
    method: () => c.req.method,
    getHeader: name => c.req.header(name),
    cookies: () => parseCookies(c.req.header('cookie')),
    body: async () => {
      try {
        return await c.req.parseBody({ all: false });
      } catch {
        // Non-form body — no token there.
        return undefined;
      }
    },
    setHeader: (name, value) => c.header(name, value),
    setHeaderIfAbsent: (name, value) => {
      // Hono's c.header() overwrites; there is no idempotent variant. Read
      // the current header off the response headers being built; on first
      // pass this is undefined so we set it.
      if (!c.res?.headers?.has?.(name)) c.header(name, value);
    },
    setCookie: (name, value, opts) => {
      c.header('Set-Cookie', serializeCookie(name, value, opts), { append: true });
    },
    json: (status, body, extraHeaders) => c.json(body, status, extraHeaders),
    noContent: (status, extraHeaders) => {
      return new Response(null, { status, headers: extraHeaders ?? {} });
    },
    ip: () => ipFromCtx(c, flags.trustProxy),
    rawReq: () => c,
    rawRes: () => c, // Hono doesn't split req/res; a single Context stands in
    decorate: (key, value) => c.set(key, value),
  };
}

function wrap(makeRunner) {
  return async function mw(c, next) {
    const runner = makeRunner(c);
    const terminal = await runner();
    if (terminal) return terminal;
    await next();
  };
}

/** Only-headers middleware. */
export function headersMiddleware(options) {
  const entries = Object.entries(buildHeaders(options ?? {}));
  return async function headersMw(c, next) {
    const ctx = makeHonoContext(c);
    await runHeaders(entries, ctx);
    await next();
  };
}

/** Only-CORS middleware. */
export function corsMiddleware(options) {
  const check = buildCorsCheck(options);
  return wrap(c => () => runCors(check, makeHonoContext(c)));
}

/** Only-CSRF middleware. */
export function csrfMiddleware(options) {
  const csrf = normalizeCsrf(options);
  return wrap(c => () => runCsrf(csrf, makeHonoContext(c)));
}

/** Only rate-limit middleware. */
export function rateLimitMiddleware(options) {
  const rl = normalizeRateLimit(options);
  return wrap(c => () => runRateLimit(rl, makeHonoContext(c, { trustProxy: rl.trustProxy })));
}

/**
 * Umbrella middleware — headers + cors + csrf + rate-limit in one `app.use`.
 *
 * @param {import('./core.js').SecurityMiddlewareOptions} options
 */
export function securityMiddleware(options = {}) {
  const cfg = normalizeUmbrella(options);
  const headersEntries = cfg.responseHeaders ? Object.entries(cfg.responseHeaders) : null;

  return async function security(c, next) {
    const ctx = makeHonoContext(c, { trustProxy: cfg.rateLimit?.trustProxy });
    // Stamp static security headers FIRST so they ride on terminal
    // rejection responses too. Hono applies context headers set via
    // c.header() onto responses built by c.json()/c.body().
    if (headersEntries) {
      await runHeaders(headersEntries, ctx);
    }
    if (cfg.corsCheck) {
      const done = await runCors(cfg.corsCheck, ctx, headersEntries);
      if (done) return done;
    }
    if (cfg.rateLimit) {
      const done = await runRateLimit(cfg.rateLimit, ctx);
      if (done) return done;
    }
    if (cfg.csrf) {
      const done = await runCsrf(cfg.csrf, ctx);
      if (done) return done;
    }
    await next();
  };
}

export default securityMiddleware;
