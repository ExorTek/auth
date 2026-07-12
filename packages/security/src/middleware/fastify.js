import fp from 'fastify-plugin';
import {
  normalizeUmbrella,
  normalizeCsrf,
  normalizeRateLimit,
  extractCsrfToken,
  issueCsrfToken,
  verifyCsrfPair,
  parseCookies,
  rateLimitDenialBody,
  buildCorsCheck,
  buildHeaders,
} from './shared.js';
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

function attachHeaders(fastify, responseHeaders) {
  const entries = Object.entries(responseHeaders);
  fastify.addHook('onSend', async (_req, reply, payload) => {
    for (const [k, v] of entries) {
      if (!reply.hasHeader(k)) {
        reply.header(k, v);
      }
    }
    return payload;
  });
}

function attachCors(fastify, corsCheck) {
  fastify.addHook('onRequest', async (req, reply) => {
    const verdict = corsCheck({
      method: req.method,
      origin: req.headers.origin,
      requestMethod: req.headers['access-control-request-method'],
      requestHeaders: req.headers['access-control-request-headers'],
    });
    const d = verdict && typeof verdict.then === 'function' ? await verdict : verdict;
    for (const [k, v] of Object.entries(d.headers)) {
      reply.header(k, v);
    }
    if (d.preflight) {
      reply.code(d.status ?? 204).send();
      return;
    }
    if (!d.allowed && req.headers.origin) {
      reply.code(403).send({ error: 'ForbiddenOrigin' });
    }
  });
}

function attachRateLimit(fastify, rateLimit) {
  fastify.addHook('onRequest', async (req, reply) => {
    const key = rateLimit.keyGenerator ? rateLimit.keyGenerator(req) : req.ip;
    if (!key) {
      return;
    }
    const result = await rateLimit.limiter.check({ key });
    const hn = rateLimit.headers;
    if (hn.retryAfter && result.retryAfter != null) {
      reply.header(hn.retryAfter, String(result.retryAfter));
    }
    if (hn.remaining) {
      reply.header(hn.remaining, String(result.remaining));
    }
    if (hn.reset && result.reset instanceof Date) {
      reply.header(hn.reset, String(Math.floor(result.reset.getTime() / 1000)));
    }
    if (!result.allowed) {
      if (rateLimit.onDenied) {
        await rateLimit.onDenied(req, reply, result);
        return;
      }
      reply.code(429).send(rateLimitDenialBody(result));
    }
  });
}

function assertCookiePluginRegistered(fastify) {
  if (!fastify.hasPlugin('@fastify/cookie')) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      "@exortek/security: csrf requires '@fastify/cookie' to be registered first. Do `await app.register(import('@fastify/cookie'))` before enabling CSRF.",
    );
  }
}

function attachCsrf(fastify, csrf) {
  assertCookiePluginRegistered(fastify);
  fastify.addHook('onRequest', async (req, reply) => {
    const cookies = req.cookies ?? parseCookies(req.headers.cookie);
    const cookieToken = cookies[csrf.cookieName];

    let pending = null;
    req.csrfToken = () => {
      if (!pending) {
        pending = issueCsrfToken(csrf);
        reply.setCookie(csrf.cookieName, pending, csrf.cookieOptions);
      }
      return pending;
    };

    if (csrf.ignoreMethods.has(req.method.toUpperCase())) {
      if (!cookieToken) {
        const t = issueCsrfToken(csrf);
        reply.setCookie(csrf.cookieName, t, csrf.cookieOptions);
        pending = t;
      }
      return;
    }

    const submitted = extractCsrfToken(csrf, req);
    if (!cookieToken || !submitted || !verifyCsrfPair(csrf, cookieToken, submitted)) {
      reply.code(403).send({ error: 'CsrfInvalid' });
    }
  });
}

/** Only-CORS plugin. */
export const corsPlugin = fp(
  async function corsPluginImpl(fastify, options) {
    attachCors(fastify, buildCorsCheck(options));
  },
  { name: '@exortek/security/cors', fastify: '>=4' },
);

/** Only-headers plugin. */
export const headersPlugin = fp(
  async function headersPluginImpl(fastify, options) {
    const map = buildHeaders(options ?? {});
    if (Object.keys(map).length) {
      attachHeaders(fastify, map);
    }
  },
  { name: '@exortek/security/headers', fastify: '>=4' },
);

/** Only-CSRF plugin. Requires `@fastify/cookie`. */
export const csrfPlugin = fp(
  async function csrfPluginImpl(fastify, options) {
    attachCsrf(fastify, normalizeCsrf(options));
  },
  { name: '@exortek/security/csrf', fastify: '>=4' },
);

/** Only rate-limit plugin. */
export const rateLimitPlugin = fp(
  async function rateLimitPluginImpl(fastify, options) {
    attachRateLimit(fastify, normalizeRateLimit(options));
  },
  { name: '@exortek/security/rate-limit', fastify: '>=4' },
);

/**
 * Umbrella plugin — headers + cors + csrf + rate-limit in one register.
 * Each concern is opt-in (`false` disables). See the individual plugins
 * above if you want to compose them yourself.
 *
 * @param {import('fastify').FastifyInstance} fastify
 * @param {import('./shared.js').SecurityMiddlewareOptions} options
 */
async function securityPluginImpl(fastify, options) {
  const cfg = normalizeUmbrella(options);
  if (cfg.responseHeaders && Object.keys(cfg.responseHeaders).length) {
    attachHeaders(fastify, cfg.responseHeaders);
  }
  if (cfg.corsCheck) {
    attachCors(fastify, cfg.corsCheck);
  }
  // Rate-limit before CSRF so a firehose of forged tokens gets throttled
  // at the door instead of paying HMAC verification cost per request.
  if (cfg.rateLimit) {
    attachRateLimit(fastify, cfg.rateLimit);
  }
  if (cfg.csrf) {
    attachCsrf(fastify, cfg.csrf);
  }
}

export const securityPlugin = fp(securityPluginImpl, {
  name: '@exortek/security',
  fastify: '>=4',
});

export default securityPlugin;
