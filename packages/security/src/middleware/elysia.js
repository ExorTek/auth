import { Elysia } from 'elysia';
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
 * Elysia adapter. Each concern is exposed as a plugin factory returning a
 * named `new Elysia()` sub-instance (same pattern used by `@elysiajs/cors`).
 * You `.use()` the result:
 *
 *   const app = new Elysia()
 *     .use(securityMiddleware({ headers, cors, csrf: { secret }, rateLimit }))
 *
 *   const app = new Elysia().use(corsMiddleware({ origin: [...] }))
 *
 * The named-plugin pattern buys us Elysia's plugin cache (identical config
 * won't rebuild the compose graph) and readable names in `.printPlugins()`.
 *
 * `onRequest` in Elysia takes ONLY a handler (no options overload), so all
 * scope-management is handled implicitly by the sub-instance. Preflight
 * traffic is caught via explicit `app.options('/', h).options('/*', h)` —
 * cleaner than an onRequest early-return trick and immune to route-level
 * `.all()` handlers intercepting OPTIONS.
 */

// `X-Forwarded-For` is client-controlled; only honour it when the caller
// opts in via `trustProxy: true` (a real proxy/CDN sits in front and
// overwrites it). Otherwise fall back to the actual socket peer address,
// which cannot be spoofed by the request body/headers.
function ipFromContext(ctx, trustProxy) {
  if (trustProxy) {
    const xff = ctx.request.headers.get('x-forwarded-for');
    if (typeof xff === 'string' && xff.length) {
      return xff.split(',')[0].trim();
    }
  }
  const serverIp = ctx.server?.requestIP?.(ctx.request);
  if (serverIp && typeof serverIp === 'object') {
    return serverIp.address;
  }
  return undefined;
}

function appendHeader(set, name, value) {
  if (!set.headers) {
    set.headers = {};
  }
  const existing = set.headers[name];
  if (Array.isArray(existing)) {
    set.headers[name] = [...existing, value];
  } else if (existing) {
    set.headers[name] = [existing, value];
  } else {
    set.headers[name] = value;
  }
}

async function runCorsNonPreflight(corsCheck, ctx) {
  const req = ctx.request;
  const origin = req.headers.get('origin');
  const verdict = corsCheck({
    method: req.method,
    origin,
    requestMethod: req.headers.get('access-control-request-method'),
    requestHeaders: req.headers.get('access-control-request-headers'),
  });
  const d = verdict && typeof verdict.then === 'function' ? await verdict : verdict;
  if (!d.allowed && origin) {
    ctx.set.status = 403;
    if (!ctx.set.headers) {
      ctx.set.headers = {};
    }
    for (const [k, v] of Object.entries(d.headers)) {
      if (!ctx.set.headers[k]) {
        ctx.set.headers[k] = v;
      }
    }
    return { error: 'ForbiddenOrigin' };
  }
  if (!ctx.set.headers) {
    ctx.set.headers = {};
  }
  for (const [k, v] of Object.entries(d.headers)) {
    if (!ctx.set.headers[k]) {
      ctx.set.headers[k] = v;
    }
  }
  return null;
}

// Preflight handler for `.options('/', h).options('/*', h)` — returns a
// Response so Elysia sends it verbatim. Merges any static security headers
// the umbrella middleware was also configured to send.
async function runCorsPreflight(corsCheck, ctx, staticHeadersEntries) {
  const req = ctx.request;
  const verdict = corsCheck({
    method: req.method,
    origin: req.headers.get('origin'),
    requestMethod: req.headers.get('access-control-request-method'),
    requestHeaders: req.headers.get('access-control-request-headers'),
  });
  const d = verdict && typeof verdict.then === 'function' ? await verdict : verdict;
  if (!d.preflight) {
    // OPTIONS without Access-Control-Request-Method — not preflight; treat
    // it like a normal request. Return null so downstream can handle.
    return null;
  }
  const merged = new Headers(d.headers);
  if (staticHeadersEntries) {
    for (const [k, v] of staticHeadersEntries) {
      if (!merged.has(k)) {
        merged.set(k, v);
      }
    }
  }
  return new Response(null, { status: d.status ?? 204, headers: merged });
}

async function runRateLimit(rateLimit, ctx) {
  const key = rateLimit.keyGenerator ? rateLimit.keyGenerator(ctx) : ipFromContext(ctx, rateLimit.trustProxy);
  if (!key) {
    return null;
  }
  const result = await rateLimit.limiter.check({ key });
  if (!ctx.set.headers) {
    ctx.set.headers = {};
  }
  const hn = rateLimit.headers;
  if (hn.retryAfter && result.retryAfter != null) {
    ctx.set.headers[hn.retryAfter] = String(result.retryAfter);
  }
  if (hn.remaining) {
    ctx.set.headers[hn.remaining] = String(result.remaining);
  }
  if (hn.reset && result.reset instanceof Date) {
    ctx.set.headers[hn.reset] = String(Math.floor(result.reset.getTime() / 1000));
  }
  if (result.allowed) {
    return null;
  }
  if (rateLimit.onDenied) {
    return await rateLimit.onDenied(ctx, result);
  }
  ctx.set.status = 429;
  return rateLimitDenialBody(result);
}

async function runCsrf(csrf, ctx) {
  const req = ctx.request;
  const cookies = parseCookies(req.headers.get('cookie'));
  const cookieToken = cookies[csrf.cookieName];

  const setCsrfCookie = value => {
    appendHeader(ctx.set, 'Set-Cookie', serializeCookie(csrf.cookieName, value, csrf.cookieOptions));
  };
  // NOTE: intentionally NOT assigning `ctx.csrfToken = ...` here — Elysia
  // wraps ctx in a Proxy under AOT, and arbitrary property assignment
  // breaks the compose graph in v1.4.x (subsequent set.headers mutations
  // are silently dropped). Handlers can call `securityMiddleware`'s
  // `issueCsrfToken` helper directly if they need a fresh token mid-handler.

  if (csrf.ignoreMethods.has(req.method.toUpperCase())) {
    if (!cookieToken) {
      const t = issueCsrfToken(csrf);
      setCsrfCookie(t);
    }
    return null;
  }

  let submitted = req.headers.get(csrf.headerName);
  if (!submitted) {
    const body = ctx.body;
    if (body && typeof body === 'object') {
      submitted = body[csrf.cookieName];
    }
  }
  if (!cookieToken || !submitted || !verifyCsrfPair(csrf, cookieToken, submitted)) {
    ctx.set.status = 403;
    return { error: 'CsrfInvalid' };
  }
  return null;
}

/** Only-headers plugin. */
export function headersMiddleware(options) {
  const map = buildHeaders(options ?? {});
  // Elysia's `.headers()` merges static values into every response — the
  // idiomatic way to apply defaults without a per-request hook.
  return new Elysia({ name: '@exortek/security/headers', aot: false }).headers(map);
}

/** Only-CORS plugin. */
export function corsMiddleware(options) {
  const check = buildCorsCheck(options);
  const preflight = async ctx => (await runCorsPreflight(check, ctx, null)) ?? new Response(null);
  return new Elysia({ name: '@exortek/security/cors', aot: false })
    .options('/', preflight)
    .options('/*', preflight)
    .onBeforeHandle({ as: 'global' }, async ({ set, request, body }) => {
      // Destructure the ctx fields we touch — Elysia's AOT strips props
      // that don't appear in the handler signature, and would drop
      // `set.headers` mutations otherwise.
      const ctx = { set, request, body };
      const terminal = await runCorsNonPreflight(check, ctx);
      if (terminal !== null && terminal !== undefined) {
        return terminal;
      }
      // Explicit `undefined` return — Elysia interprets `null` as an empty
      // response body, which would drop set.headers mutations on the floor.
    });
}

/** Only-CSRF plugin. */
export function csrfMiddleware(options) {
  const csrf = normalizeCsrf(options);
  return new Elysia({ name: '@exortek/security/csrf', aot: false }).onBeforeHandle(
    { as: 'global' },
    async ({ set, request, body }) => {
      const ctx = { set, request, body };
      const terminal = await runCsrf(csrf, ctx);
      if (terminal !== null && terminal !== undefined) {
        return terminal;
      }
    },
  );
}

/** Only rate-limit plugin. */
export function rateLimitMiddleware(options) {
  const rl = normalizeRateLimit(options);
  return new Elysia({ name: '@exortek/security/rate-limit', aot: false }).onBeforeHandle(
    { as: 'global' },
    async ({ set, request, server }) => {
      const ctx = { set, request, server };
      const terminal = await runRateLimit(rl, ctx);
      if (terminal !== null && terminal !== undefined) {
        return terminal;
      }
    },
  );
}

/**
 * Umbrella plugin — headers + cors + csrf + rate-limit in one `.use()`.
 *
 * @param {import('./core.js').SecurityMiddlewareOptions} options
 */
export function securityMiddleware(options = {}) {
  const cfg = normalizeUmbrella(options);
  const headersEntries = cfg.responseHeaders ? Object.entries(cfg.responseHeaders) : null;

  const app = new Elysia({ name: '@exortek/security', aot: false });

  if (cfg.responseHeaders) {
    app.headers(cfg.responseHeaders);
  }

  if (cfg.corsCheck) {
    const preflight = async ctx => (await runCorsPreflight(cfg.corsCheck, ctx, headersEntries)) ?? new Response(null);
    app.options('/', preflight).options('/*', preflight);
  }

  if (cfg.corsCheck || cfg.rateLimit || cfg.csrf) {
    app.onBeforeHandle({ as: 'global' }, async ({ set, request, body, server }) => {
      const ctx = { set, request, body, server };
      if (cfg.corsCheck) {
        const terminal = await runCorsNonPreflight(cfg.corsCheck, ctx);
        if (terminal !== null && terminal !== undefined) {
          return terminal;
        }
      }
      if (cfg.rateLimit) {
        const terminal = await runRateLimit(cfg.rateLimit, ctx);
        if (terminal !== null && terminal !== undefined) {
          return terminal;
        }
      }
      if (cfg.csrf) {
        const terminal = await runCsrf(cfg.csrf, ctx);
        if (terminal !== null && terminal !== undefined) {
          return terminal;
        }
      }
    });
  }

  return app;
}

export default securityMiddleware;
