import {
  normalizeUmbrella,
  normalizeCsrf,
  normalizeRateLimit,
  issueCsrfToken,
  verifyCsrfPair,
  parseCookies,
  serializeCookie,
  rateLimitDenialBody,
  buildCorsCheck,
  buildHeaders,
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
 * Cloudflare. With neither `trustProxy` nor `keyGenerator`, no key can be
 * derived and the request is not counted (fail-open on IP, but never
 * silently spoofable).
 */

function ipFromHeaders(c, trustProxy) {
  if (!trustProxy) {
    return undefined;
  }
  const xff = c.req.header('x-forwarded-for');
  if (typeof xff === 'string' && xff.length) {
    return xff.split(',')[0].trim();
  }
  return undefined;
}

async function runCors(corsCheck, c, responseHeadersEntries) {
  const verdict = corsCheck({
    method: c.req.method,
    origin: c.req.header('origin'),
    requestMethod: c.req.header('access-control-request-method'),
    requestHeaders: c.req.header('access-control-request-headers'),
  });
  const d = verdict && typeof verdict.then === 'function' ? await verdict : verdict;
  if (d.preflight) {
    // Preflight is a terminal response — merge CORS headers with any static
    // security headers the caller wanted on every response.
    const merged = { ...d.headers };
    if (responseHeadersEntries) {
      for (const [k, v] of responseHeadersEntries) {
        merged[k] = merged[k] ?? v;
      }
    }
    return new Response(null, { status: d.status ?? 204, headers: merged });
  }
  if (!d.allowed && c.req.header('origin')) {
    return c.json({ error: 'ForbiddenOrigin' }, 403, d.headers);
  }
  for (const [k, v] of Object.entries(d.headers)) {
    c.header(k, v);
  }
  return null;
}

async function runRateLimit(rateLimit, c) {
  const key = rateLimit.keyGenerator ? rateLimit.keyGenerator(c) : ipFromHeaders(c, rateLimit.trustProxy);
  if (!key) {
    return null;
  }
  const result = await rateLimit.limiter.check({ key });
  const hn = rateLimit.headers;
  if (hn.retryAfter && result.retryAfter != null) {
    c.header(hn.retryAfter, String(result.retryAfter));
  }
  if (hn.remaining) {
    c.header(hn.remaining, String(result.remaining));
  }
  if (hn.reset && result.reset instanceof Date) {
    c.header(hn.reset, String(Math.floor(result.reset.getTime() / 1000)));
  }
  if (result.allowed) {
    return null;
  }
  if (rateLimit.onDenied) {
    const r = await rateLimit.onDenied(c, result);
    return r instanceof Response ? r : c.body(null);
  }
  return c.json(rateLimitDenialBody(result), 429);
}

async function runCsrf(csrf, c) {
  const cookies = parseCookies(c.req.header('cookie'));
  const cookieToken = cookies[csrf.cookieName];

  let pending = null;
  const setCsrfCookie = value => {
    c.header('Set-Cookie', serializeCookie(csrf.cookieName, value, csrf.cookieOptions), { append: true });
  };
  c.set('csrfToken', () => {
    if (!pending) {
      pending = issueCsrfToken(csrf);
      setCsrfCookie(pending);
    }
    return pending;
  });

  if (csrf.ignoreMethods.has(c.req.method.toUpperCase())) {
    if (!cookieToken) {
      const t = issueCsrfToken(csrf);
      setCsrfCookie(t);
    }
    return null;
  }

  // Header path is cheap; fall back to form body only if the header is empty.
  let submitted = c.req.header(csrf.headerName);
  if (!submitted) {
    try {
      const body = await c.req.parseBody({ all: false });
      submitted = body?.[csrf.cookieName];
    } catch {
      // Non-form body — treat as missing token.
    }
  }
  if (!cookieToken || !submitted || !verifyCsrfPair(csrf, cookieToken, submitted)) {
    return c.json({ error: 'CsrfInvalid' }, 403);
  }
  return null;
}

/** Only-headers middleware. */
export function headersMiddleware(options) {
  const map = buildHeaders(options ?? {});
  const entries = Object.entries(map);
  return async function headersMw(c, next) {
    for (const [k, v] of entries) {
      c.header(k, v);
    }
    await next();
  };
}

/** Only-CORS middleware. */
export function corsMiddleware(options) {
  const check = buildCorsCheck(options);
  return async function corsMw(c, next) {
    const terminal = await runCors(check, c, null);
    if (terminal) {
      return terminal;
    }
    await next();
  };
}

/** Only-CSRF middleware. */
export function csrfMiddleware(options) {
  const csrf = normalizeCsrf(options);
  return async function csrfMw(c, next) {
    const terminal = await runCsrf(csrf, c);
    if (terminal) {
      return terminal;
    }
    await next();
  };
}

/** Only rate-limit middleware. */
export function rateLimitMiddleware(options) {
  const rl = normalizeRateLimit(options);
  return async function rateLimitMw(c, next) {
    const terminal = await runRateLimit(rl, c);
    if (terminal) {
      return terminal;
    }
    await next();
  };
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
    // Stamp static security headers FIRST so they ride on terminal
    // rejection responses too (a 429 / 403 from rate-limit or csrf must
    // still carry CSP / HSTS). Matches the Express and Elysia adapters,
    // which also apply headers to every response, not just passed-through
    // ones. Hono applies context headers set via c.header() onto responses
    // built by c.json()/c.body().
    if (headersEntries) {
      for (const [k, v] of headersEntries) {
        c.header(k, v);
      }
    }
    if (cfg.corsCheck) {
      const terminal = await runCors(cfg.corsCheck, c, headersEntries);
      if (terminal) {
        return terminal;
      }
    }
    if (cfg.rateLimit) {
      const terminal = await runRateLimit(cfg.rateLimit, c);
      if (terminal) {
        return terminal;
      }
    }
    if (cfg.csrf) {
      const terminal = await runCsrf(cfg.csrf, c);
      if (terminal) {
        return terminal;
      }
    }
    await next();
  };
}

export default securityMiddleware;
