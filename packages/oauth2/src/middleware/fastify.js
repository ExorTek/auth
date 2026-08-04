/**
 * Fastify adapter for the RP social-login flow. Serves a browser-redirect
 * flow (`mode: 'web'`, default) or a JSON flow for mobile / SPA / CLI
 * clients (`mode: 'api'`) — same `createOAuth` core, different transport.
 *
 *   import { oauthLoginPlugin } from '@exortek/oauth2/fastify';
 *   await app.register(oauthLoginPlugin, { oauth, cookie: { secret }, onSuccess: ({ request, reply, user }) => {...} });
 *   await app.register(oauthLoginPlugin, { oauth, mode: 'api', secret });
 *
 * A Fastify route handler must produce the reply, so `onSuccess` is where
 * the app takes over; without it a minimal `{ user, provider }` response
 * is sent (never the tokens). The `callbackPath` MUST equal the `callback`
 * template given to createOAuth.
 */
import { fastifyPlugin } from '@exortek/shared/fastify-plugin';
import { parseCookies, serialiseCookie, serialiseDeleteCookie } from '@exortek/shared/cookie';
import { isFunction, isInteger, isObject } from '@exortek/shared/predicates';

import { normalizeLoginConfig, startLogin, completeLogin } from './core.js';

/**
 * @param {any} fastify
 * @param {import('./core.js').LoginConfig} options
 */
async function oauthLoginPluginFn(fastify, options) {
  const cfg = normalizeLoginConfig(options);

  // Route-scoped only: this plugin registers two endpoints and nothing
  // app-wide — no global hook or error handler that would run on (or
  // hijack) the rest of the backend's requests.
  if (cfg.mode === 'api') {
    fastify.post(cfg.loginPath, guard(cfg, apiStart(cfg)));
    fastify.post(cfg.callbackPath, guard(cfg, apiCallback(cfg)));
  } else {
    fastify.get(cfg.loginPath, guard(cfg, webStart(cfg)));
    fastify.get(cfg.callbackPath, guard(cfg, webCallback(cfg)));
  }
}

function webStart(cfg) {
  return async (request, reply) => {
    const { authorizeUrl, setCookie } = await startLogin(cfg, request.params.provider, {});
    if (setCookie) {
      reply.header('set-cookie', serialiseCookie(setCookie.name, setCookie.value, setCookie.options));
    }
    return reply.redirect(authorizeUrl);
  };
}

function webCallback(cfg) {
  return async (request, reply) => {
    const cookies = parseCookies(request.headers.cookie);
    const { result, clearCookie } = await completeLogin(cfg, request.params.provider, request.query, {
      cookieValue: cookies[cfg.cookieName],
    });
    if (clearCookie) {
      reply.header('set-cookie', serialiseDeleteCookie(clearCookie, { path: cfg.cookieOptions.path }));
    }
    return finishHandoff(cfg, request, reply, result);
  };
}

function apiStart(cfg) {
  return async (request, reply) => {
    const { authorizeUrl, session, warnings } = await startLogin(cfg, request.params.provider, {});
    return reply.send({ authorizeUrl, session, warnings });
  };
}

function apiCallback(cfg) {
  return async (request, reply) => {
    const body = isObject(request.body) ? request.body : {};
    const { session, ...query } = body;
    const { result } = await completeLogin(cfg, request.params.provider, query, { session });
    return finishHandoff(cfg, request, reply, result);
  };
}

/**
 * Per-route error handling — a flow failure becomes the caller's
 * `onError` or a typed reply, without a global `setErrorHandler` that
 * would swallow the rest of the app's errors.
 *
 * @param {ReturnType<typeof normalizeLoginConfig>} cfg
 * @param {(request: any, reply: any) => Promise<unknown>} handler
 */
function guard(cfg, handler) {
  return async (request, reply) => {
    try {
      return await handler(request, reply);
    } catch (error) {
      if (isFunction(cfg.onError)) {
        return cfg.onError({ request, reply, error });
      }
      const status = isInteger(error.status) ? error.status : 500;
      return reply.status(status).send({ error: error.code ?? 'oauth_error', error_description: error.message });
    }
  };
}

/**
 * @param {ReturnType<typeof normalizeLoginConfig>} cfg
 * @param {any} request @param {any} reply @param {object} result
 */
function finishHandoff(cfg, request, reply, result) {
  if (isFunction(cfg.onSuccess)) {
    return cfg.onSuccess({ request, reply, ...result });
  }
  return reply.send({ user: result.user, warnings: result.warnings, provider: result.provider });
}

export const oauthLoginPlugin = fastifyPlugin(oauthLoginPluginFn, {
  fastify: '>=4',
  name: '@exortek/oauth2-login',
});
