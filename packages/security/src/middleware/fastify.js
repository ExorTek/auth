import fp from 'fastify-plugin';
import {
  normalizeUmbrella,
  normalizeCsrf,
  normalizeRateLimit,
  parseCookies,
  buildCorsCheck,
  buildHeaders,
  runCors,
  runRateLimit,
  runCsrf,
} from './core.js';
import { SecurityError, ErrorCode } from '../internal/errors.js';

/*
 * Fastify adapter. Each concern is exposed both as its own plugin
 * (`headersPlugin`, `corsPlugin`, `csrfPlugin`, `rateLimitPlugin`) and as
 * part of the umbrella `securityPlugin(options)`. All are wrapped with
 * `fastify-plugin` so their hooks apply globally (bypassing per-plugin
 * encapsulation).
 *
 * Usage:
 *   import { securityPlugin, corsPlugin } from '@exortek/security/fastify'
 *
 *   // Just CORS
 *   await app.register(corsPlugin, { origin: ['https://app.example.com'] })
 *
 *   // Full stack
 *   await app.register(securityPlugin, {
 *     headers: {...}, cors: {...}, csrf: { secret }, rateLimit: { limiter },
 *   })
 */

/**
 * Build the framework-neutral `AdapterContext` from Fastify's
 * `(request, reply)`. Runners in `core.js` do the actual work.
 *
 * @param {any} request
 * @param {any} reply
 * @param {{ hasFastifyCookie?: boolean }} [flags]
 * @returns {import('./core.js').AdapterContext}
 */
function makeFastifyContext(request, reply, flags = {}) {
  return {
    method: () => request.method,
    getHeader: name => {
      const v = request.headers[name.toLowerCase()];
      return Array.isArray(v) ? v[0] : v;
    },
    cookies: () => request.cookies ?? parseCookies(request.headers.cookie),
    body: () => request.body,
    setHeader: (name, value) => reply.header(name, value),
    setHeaderIfAbsent: (name, value) => {
      if (!reply.hasHeader(name)) {
        reply.header(name, value);
      }
    },
    setCookie: (name, value, opts) => {
      // @fastify/cookie handles the Set-Cookie stack correctly on Fastify;
      // fall back to a raw `reply.header('Set-Cookie', ...)` only if
      // callers went bare. `attachCsrf` asserts the plugin is present, so
      // in practice we always hit the first branch.
      if (flags.hasFastifyCookie && typeof reply.setCookie === 'function') {
        reply.setCookie(name, value, opts);
      } else {
        reply.header('Set-Cookie', value); // callers are expected to use @fastify/cookie
      }
    },
    json: (status, body, extraHeaders) => {
      if (extraHeaders) {
        for (const [k, v] of Object.entries(extraHeaders)) {
          reply.header(k, v);
        }
      }
      reply.code(status).send(body);
      return true;
    },
    noContent: (status, extraHeaders) => {
      if (extraHeaders) {
        for (const [k, v] of Object.entries(extraHeaders)) {
          reply.header(k, v);
        }
      }
      reply.code(status).send();
      return true;
    },
    ip: () => request.ip,
    rawReq: () => request,
    rawRes: () => reply,
    decorate: (key, value) => {
      request[key] = value;
    },
  };
}

function attachRunner(fastify, runner, hookName = 'onRequest') {
  fastify.addHook(hookName, async (request, reply) => {
    const ctx = makeFastifyContext(request, reply, { hasFastifyCookie: fastify.hasPlugin('@fastify/cookie') });
    await runner(ctx);
  });
}

/** Only-CORS plugin. */
export const corsPlugin = fp(
  async function corsPluginImpl(fastify, options) {
    const check = buildCorsCheck(options);
    attachRunner(fastify, ctx => runCors(check, ctx));
  },
  { name: '@exortek/security/cors', fastify: '>=4' },
);

/** Only-headers plugin. */
export const headersPlugin = fp(
  async function headersPluginImpl(fastify, options) {
    const map = buildHeaders(options ?? {});
    if (Object.keys(map).length === 0) {
      return;
    }
    const entries = Object.entries(map);
    // Headers apply on the way out (onSend) so terminal responses from
    // other hooks (CORS preflight, CSRF deny) also carry them.
    fastify.addHook('onSend', async (_req, reply, payload) => {
      for (const [k, v] of entries) {
        if (!reply.hasHeader(k)) {
          reply.header(k, v);
        }
      }
      return payload;
    });
  },
  { name: '@exortek/security/headers', fastify: '>=4' },
);

/** Only-CSRF plugin. Requires `@fastify/cookie`. */
export const csrfPlugin = fp(
  async function csrfPluginImpl(fastify, options) {
    const csrf = normalizeCsrf(options);
    if (!fastify.hasPlugin('@fastify/cookie')) {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        "@exortek/security: csrf requires '@fastify/cookie' to be registered first. Do `await app.register(import('@fastify/cookie'))` before enabling CSRF.",
      );
    }
    attachRunner(fastify, ctx => runCsrf(csrf, ctx));
  },
  { name: '@exortek/security/csrf', fastify: '>=4' },
);

/** Only rate-limit plugin. */
export const rateLimitPlugin = fp(
  async function rateLimitPluginImpl(fastify, options) {
    const rl = normalizeRateLimit(options);
    attachRunner(fastify, ctx => runRateLimit(rl, ctx));
  },
  { name: '@exortek/security/rate-limit', fastify: '>=4' },
);

/**
 * Umbrella plugin — headers + cors + csrf + rate-limit in one register.
 * Each concern is opt-in (`false` disables). See the individual plugins
 * above if you want to compose them yourself.
 *
 * @param {import('fastify').FastifyInstance} fastify
 * @param {import('./core.js').SecurityMiddlewareOptions} options
 */
async function securityPluginImpl(fastify, options) {
  const cfg = normalizeUmbrella(options);
  const headersEntries = cfg.responseHeaders ? Object.entries(cfg.responseHeaders) : null;

  if (headersEntries) {
    fastify.addHook('onSend', async (_req, reply, payload) => {
      for (const [k, v] of headersEntries) {
        if (!reply.hasHeader(k)) {
          reply.header(k, v);
        }
      }
      return payload;
    });
  }

  if (cfg.corsCheck) {
    attachRunner(fastify, ctx => runCors(cfg.corsCheck, ctx, headersEntries));
  }
  // Rate-limit before CSRF so a firehose of forged tokens gets throttled
  // at the door instead of paying HMAC verification cost per request.
  if (cfg.rateLimit) {
    attachRunner(fastify, ctx => runRateLimit(cfg.rateLimit, ctx));
  }
  if (cfg.csrf) {
    if (!fastify.hasPlugin('@fastify/cookie')) {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        "@exortek/security: csrf requires '@fastify/cookie' to be registered first. Do `await app.register(import('@fastify/cookie'))` before enabling CSRF.",
      );
    }
    attachRunner(fastify, ctx => runCsrf(cfg.csrf, ctx));
  }
}

export const securityPlugin = fp(securityPluginImpl, {
  name: '@exortek/security',
  fastify: '>=4',
});

export default securityPlugin;
