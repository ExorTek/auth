import { Elysia } from 'elysia';
import {
  normalizeUmbrella,
  normalizeCsrf,
  normalizeRateLimit,
  parseCookies,
  serializeCookie,
  buildCorsCheck,
  buildHeaders,
  runCors,
  runRateLimit,
  runCsrf,
} from './core.js';

/*
 * Elysia adapter. Each concern is exposed as a plugin factory returning a
 * named `new Elysia()` sub-instance (same pattern used by `@elysiajs/cors`).
 * You `.use()` the result:
 *
 *   const app = new Elysia()
 *     .use(securityMiddleware({ headers, cors, csrf: { secret }, rateLimit }))
 *
 * Preflight traffic is caught via explicit `.options('/', h).options('/*', h)`
 * — cleaner than an onRequest early-return trick and immune to route-level
 * `.all()` handlers intercepting OPTIONS.
 *
 * NOTE on decoration: Elysia's AOT wraps the ctx in a Proxy; arbitrary
 * property assignment breaks the compose graph (subsequent set.headers
 * mutations get silently dropped in v1.4.x). `runCsrf` calls
 * `ctx.decorate('csrfToken', ...)` — the Elysia context intentionally
 * makes that a no-op. Handlers that need a fresh CSRF token mid-handler
 * can import `issueCsrfToken` from `@exortek/security` directly.
 */

// `X-Forwarded-For` is client-controlled; only honour it when the caller
// opts in via `trustProxy: true` (a real proxy/CDN sits in front and
// overwrites it). Otherwise fall back to the actual socket peer address,
// which cannot be spoofed by the request body/headers.
function ipFromCtx(elysia, trustProxy) {
  if (trustProxy) {
    const xff = elysia.request.headers.get('x-forwarded-for');
    if (typeof xff === 'string' && xff.length) {
      return xff.split(',')[0].trim();
    }
  }
  const serverIp = elysia.server?.requestIP?.(elysia.request);
  if (serverIp && typeof serverIp === 'object') {
    return serverIp.address;
  }
  return undefined;
}

function appendSetCookieOnSet(set, value) {
  if (!set.headers) set.headers = {};
  const existing = set.headers['Set-Cookie'];
  if (Array.isArray(existing)) {
    set.headers['Set-Cookie'] = [...existing, value];
  } else if (existing) {
    set.headers['Set-Cookie'] = [existing, value];
  } else {
    set.headers['Set-Cookie'] = value;
  }
}

/**
 * Build the framework-neutral `AdapterContext` from Elysia's destructured
 * handler args `{ set, request, body, server }`.
 *
 * @param {{ set: any, request: Request, body?: unknown, server?: any }} elysia
 * @param {{ trustProxy?: boolean }} [flags]
 * @returns {import('./core.js').AdapterContext}
 */
function makeElysiaContext(elysia, flags = {}) {
  const { set, request, body, server } = elysia;
  const ensureHeaders = () => {
    if (!set.headers) set.headers = {};
    return set.headers;
  };
  return {
    method: () => request.method,
    getHeader: name => request.headers.get(name) ?? undefined,
    cookies: () => parseCookies(request.headers.get('cookie')),
    body: () => body,
    setHeader: (name, value) => {
      ensureHeaders()[name] = value;
    },
    setHeaderIfAbsent: (name, value) => {
      const h = ensureHeaders();
      if (!h[name]) h[name] = value;
    },
    setCookie: (name, value, opts) => {
      appendSetCookieOnSet(set, serializeCookie(name, value, opts));
    },
    json: (status, jsonBody, extraHeaders) => {
      set.status = status;
      if (extraHeaders) {
        const h = ensureHeaders();
        for (const [k, v] of Object.entries(extraHeaders)) {
          if (!h[k]) h[k] = v;
        }
      }
      return jsonBody;
    },
    noContent: (status, extraHeaders) => {
      const headers = new Headers();
      if (extraHeaders) {
        for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v);
      }
      // Preflight callers expect a real Response; onBeforeHandle can also
      // handle it (Elysia sends the Response verbatim).
      return new Response(null, { status, headers });
    },
    ip: () => ipFromCtx({ request, server }, flags.trustProxy),
    rawReq: () => elysia,
    rawRes: () => null,
    // Deliberate no-op — see file docblock.
    decorate: () => {},
  };
}

/** Only-headers plugin. */
export function headersMiddleware(options) {
  const map = buildHeaders(options ?? {});
  return new Elysia({ name: '@exortek/security/headers', aot: false }).headers(map);
}

/** Only-CORS plugin. */
export function corsMiddleware(options) {
  const check = buildCorsCheck(options);
  const preflight = async ({ set, request }) => {
    const ctx = makeElysiaContext({ set, request });
    const terminal = await runCors(check, ctx);
    return terminal ?? new Response(null);
  };
  return new Elysia({ name: '@exortek/security/cors', aot: false })
    .options('/', preflight)
    .options('/*', preflight)
    .onBeforeHandle({ as: 'global' }, async ({ set, request }) => {
      const ctx = makeElysiaContext({ set, request });
      const terminal = await runCors(check, ctx);
      // runCors returns a Response only for preflight; here it's either the
      // deny 403 json body (via ctx.json which sets set.status) or null.
      if (terminal !== null && terminal !== undefined && !(terminal instanceof Response)) {
        return terminal;
      }
    });
}

/** Only-CSRF plugin. */
export function csrfMiddleware(options) {
  const csrf = normalizeCsrf(options);
  return new Elysia({ name: '@exortek/security/csrf', aot: false }).onBeforeHandle(
    { as: 'global' },
    // Destructure explicitly — Elysia's compose graph tracks which ctx
    // fields the handler reads, and drops set.headers mutations from
    // handlers that don't name `set`.
    async ({ set, request, body }) => {
      const ctx = makeElysiaContext({ set, request, body });
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
      const ctx = makeElysiaContext({ set, request, server }, { trustProxy: rl.trustProxy });
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
    const preflight = async ({ set, request }) => {
      const ctx = makeElysiaContext({ set, request });
      const terminal = await runCors(cfg.corsCheck, ctx, headersEntries);
      return terminal ?? new Response(null);
    };
    app.options('/', preflight).options('/*', preflight);
  }

  if (cfg.corsCheck || cfg.rateLimit || cfg.csrf) {
    app.onBeforeHandle({ as: 'global' }, async ({ set, request, body, server }) => {
      const ctx = makeElysiaContext({ set, request, body, server }, { trustProxy: cfg.rateLimit?.trustProxy });
      if (cfg.corsCheck) {
        const terminal = await runCors(cfg.corsCheck, ctx);
        if (terminal !== null && terminal !== undefined && !(terminal instanceof Response)) {
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
