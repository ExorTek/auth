import { appendSetCookieHeader } from '@exortek/shared/http';

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
 * Express adapter. Each concern is exposed as its own middleware factory:
 *   headersMiddleware, corsMiddleware, csrfMiddleware, rateLimitMiddleware,
 * plus the bundle:
 *   securityMiddleware.
 *
 * Enable `app.set('trust proxy', true)` if you sit behind a load balancer,
 * otherwise `req.ip` reports the proxy IP and rate-limit buckets collapse.
 */

/**
 * Build the framework-neutral `AdapterContext` from Express's
 * `(req, res)`. Runners in `core.js` do the actual work.
 *
 * @param {any} req
 * @param {any} res
 * @returns {import('./core.js').AdapterContext}
 */
function makeExpressContext(req, res) {
  const appendResponseCookie = value => {
    // Prefer `appendHeader` (Express 5) so multiple middlewares' Set-Cookie
    // headers don't clobber each other; on Express 4 read the current
    // value and stack via the shared helper so we don't drop a
    // previously-set cookie either.
    if (typeof res.appendHeader === 'function') {
      res.appendHeader('Set-Cookie', value);
    } else {
      res.setHeader('Set-Cookie', appendSetCookieHeader(res.getHeader('Set-Cookie'), value));
    }
  };
  return {
    method: () => req.method,
    getHeader: name => {
      const v = req.headers[name.toLowerCase()];
      return Array.isArray(v) ? v[0] : v;
    },
    cookies: () => req.cookies ?? parseCookies(req.headers.cookie),
    body: () => req.body,
    setHeader: (name, value) => {
      res.setHeader(name, value);
    },
    setHeaderIfAbsent: (name, value) => {
      if (!res.getHeader(name)) res.setHeader(name, value);
    },
    setCookie: (name, value, opts) => {
      appendResponseCookie(serializeCookie(name, value, opts));
    },
    json: (status, body, extraHeaders) => {
      res.statusCode = status;
      if (extraHeaders) {
        for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
      }
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(body));
      return true;
    },
    noContent: (status, extraHeaders) => {
      res.statusCode = status;
      if (extraHeaders) {
        for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
      }
      res.end();
      return true;
    },
    ip: () => req.ip,
    rawReq: () => req,
    rawRes: () => res,
    decorate: (key, value) => {
      req[key] = value;
    },
  };
}

function wrap(runner) {
  return async function mw(req, res, next) {
    try {
      const ctx = makeExpressContext(req, res);
      const terminated = await runner(ctx);
      if (!terminated) next();
    } catch (err) {
      next(err);
    }
  };
}

/** Only-headers middleware. */
export function headersMiddleware(options) {
  const entries = Object.entries(buildHeaders(options ?? {}));
  return wrap(async ctx => runHeaders(entries, ctx));
}

/** Only-CORS middleware. */
export function corsMiddleware(options) {
  const check = buildCorsCheck(options);
  return wrap(async ctx => runCors(check, ctx));
}

/** Only-CSRF middleware. */
export function csrfMiddleware(options) {
  const csrf = normalizeCsrf(options);
  return wrap(async ctx => runCsrf(csrf, ctx));
}

/** Only rate-limit middleware. */
export function rateLimitMiddleware(options) {
  const rl = normalizeRateLimit(options);
  return wrap(async ctx => runRateLimit(rl, ctx));
}

/**
 * Umbrella middleware — headers + cors + csrf + rate-limit in one `app.use`.
 * Each concern is opt-in; set to `false` to skip. See the individual
 * factories above if you want to compose them yourself.
 *
 * @param {import('./core.js').SecurityMiddlewareOptions} options
 */
export function securityMiddleware(options = {}) {
  const cfg = normalizeUmbrella(options);
  const headersEntries = cfg.responseHeaders ? Object.entries(cfg.responseHeaders) : null;

  return wrap(async ctx => {
    if (headersEntries) {
      await runHeaders(headersEntries, ctx);
    }
    if (cfg.corsCheck) {
      const done = await runCors(cfg.corsCheck, ctx, headersEntries);
      if (done) return done;
    }
    // Rate-limit before CSRF so a firehose of forged tokens gets throttled
    // at the door instead of paying HMAC verification cost per request.
    if (cfg.rateLimit) {
      const done = await runRateLimit(cfg.rateLimit, ctx);
      if (done) return done;
    }
    if (cfg.csrf) {
      const done = await runCsrf(cfg.csrf, ctx);
      if (done) return done;
    }
    return null;
  });
}

export default securityMiddleware;
