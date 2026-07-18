import { appendSetCookieHeader } from '@exortek/shared/http';

import {
  normalizeUmbrella,
  normalizeCsrf,
  normalizeRateLimit,
  extractCsrfToken,
  issueCsrfToken,
  verifyCsrfPair,
  parseCookies,
  serializeCookie,
  rateLimitDenialBody,
  buildCorsCheck,
  buildHeaders,
} from './shared.js';

/*
 * Express adapter. Each concern is exposed as its own middleware factory:
 *   headersMiddleware, corsMiddleware, csrfMiddleware, rateLimitMiddleware,
 * plus the bundle:
 *   securityMiddleware.
 *
 * Enable `app.set('trust proxy', true)` if you sit behind a load balancer,
 * otherwise `req.ip` reports the proxy IP and rate-limit buckets collapse.
 */

function setHeaderIfAbsent(res, k, v) {
  if (!res.getHeader(k)) {
    res.setHeader(k, v);
  }
}

function writeJson(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(body));
}

// Per-request logic for each concern. Returns `true` if the middleware
// terminated the response (caller should NOT call next()).

async function runHeaders(headersEntries, res) {
  for (const [k, v] of headersEntries) {
    setHeaderIfAbsent(res, k, v);
  }
  return false;
}

async function runCors(corsCheck, req, res) {
  const verdict = corsCheck({
    method: req.method,
    origin: req.headers.origin,
    requestMethod: req.headers['access-control-request-method'],
    requestHeaders: req.headers['access-control-request-headers'],
  });
  const d = verdict && typeof verdict.then === 'function' ? await verdict : verdict;
  for (const [k, v] of Object.entries(d.headers)) {
    res.setHeader(k, v);
  }
  if (d.preflight) {
    res.statusCode = d.status ?? 204;
    res.end();
    return true;
  }
  if (!d.allowed && req.headers.origin) {
    writeJson(res, 403, { error: 'ForbiddenOrigin' });
    return true;
  }
  return false;
}

async function runRateLimit(rateLimit, req, res) {
  const key = rateLimit.keyGenerator ? rateLimit.keyGenerator(req) : req.ip;
  if (!key) {
    return false;
  }
  const result = await rateLimit.limiter.check({ key });
  const hn = rateLimit.headers;
  if (hn.retryAfter && result.retryAfter != null) {
    res.setHeader(hn.retryAfter, String(result.retryAfter));
  }
  if (hn.remaining) {
    res.setHeader(hn.remaining, String(result.remaining));
  }
  if (hn.reset && result.reset instanceof Date) {
    res.setHeader(hn.reset, String(Math.floor(result.reset.getTime() / 1000)));
  }
  if (result.allowed) {
    return false;
  }
  if (rateLimit.onDenied) {
    await rateLimit.onDenied(req, res, result);
    return true;
  }
  writeJson(res, 429, rateLimitDenialBody(result));
  return true;
}

async function runCsrf(csrf, req, res) {
  const cookies = req.cookies ?? parseCookies(req.headers.cookie);
  const cookieToken = cookies[csrf.cookieName];

  let pending = null;
  const scheduleSetCookie = value => {
    const serialized = serializeCookie(csrf.cookieName, value, csrf.cookieOptions);
    // Prefer `appendHeader` (Express 5) so multiple middlewares' Set-Cookie
    // headers don't clobber each other; on Express 4 read the current
    // value and stack via the shared helper so we don't drop a
    // previously-set cookie either.
    if (typeof res.appendHeader === 'function') {
      res.appendHeader('Set-Cookie', serialized);
    } else {
      res.setHeader('Set-Cookie', appendSetCookieHeader(res.getHeader('Set-Cookie'), serialized));
    }
  };

  req.csrfToken = () => {
    if (!pending) {
      pending = issueCsrfToken(csrf);
      scheduleSetCookie(pending);
    }
    return pending;
  };

  if (csrf.ignoreMethods.has(req.method.toUpperCase())) {
    if (!cookieToken) {
      req.csrfToken();
    }
    return false;
  }

  const submitted = extractCsrfToken(csrf, req);
  if (!cookieToken || !submitted || !verifyCsrfPair(csrf, cookieToken, submitted)) {
    writeJson(res, 403, { error: 'CsrfInvalid' });
    return true;
  }
  return false;
}

/** Only-headers middleware. */
export function headersMiddleware(options) {
  const map = buildHeaders(options ?? {});
  const entries = Object.entries(map);
  return async function headersMw(_req, res, next) {
    try {
      await runHeaders(entries, res);
      next();
    } catch (err) {
      next(err);
    }
  };
}

/** Only-CORS middleware. */
export function corsMiddleware(options) {
  const check = buildCorsCheck(options);
  return async function corsMw(req, res, next) {
    try {
      const done = await runCors(check, req, res);
      if (!done) {
        next();
      }
    } catch (err) {
      next(err);
    }
  };
}

/** Only-CSRF middleware. */
export function csrfMiddleware(options) {
  const csrf = normalizeCsrf(options);
  return async function csrfMw(req, res, next) {
    try {
      const done = await runCsrf(csrf, req, res);
      if (!done) {
        next();
      }
    } catch (err) {
      next(err);
    }
  };
}

/** Only rate-limit middleware. */
export function rateLimitMiddleware(options) {
  const rl = normalizeRateLimit(options);
  return async function rateLimitMw(req, res, next) {
    try {
      const done = await runRateLimit(rl, req, res);
      if (!done) {
        next();
      }
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Umbrella middleware — headers + cors + csrf + rate-limit in one `app.use`.
 * Each concern is opt-in; set to `false` to skip. See the individual
 * factories above if you want to compose them yourself.
 *
 * @param {import('./shared.js').SecurityMiddlewareOptions} options
 */
export function securityMiddleware(options = {}) {
  const cfg = normalizeUmbrella(options);
  const headersEntries = cfg.responseHeaders ? Object.entries(cfg.responseHeaders) : null;

  return async function security(req, res, next) {
    try {
      if (headersEntries) {
        await runHeaders(headersEntries, res);
      }
      if (cfg.corsCheck && (await runCors(cfg.corsCheck, req, res))) {
        return;
      }
      if (cfg.rateLimit && (await runRateLimit(cfg.rateLimit, req, res))) {
        return;
      }
      if (cfg.csrf && (await runCsrf(cfg.csrf, req, res))) {
        return;
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

export default securityMiddleware;
