/**
 * Express adapter for the RP social-login flow. Serves either a
 * browser-redirect flow (`mode: 'web'`, the default) or a JSON flow for
 * mobile / SPA / CLI clients (`mode: 'api'`) — same `createOAuth` core,
 * different transport.
 *
 * Two ways to use it — pick whichever fits how you like to route:
 *
 *   import { oauthLogin, mountOAuthLogin } from '@exortek/oauth2/express';
 *
 *   // (a) Handlers you drop into your OWN routes (passport-style):
 *   const login = oauthLogin({ oauth, cookie: { secret } });
 *   app.get('/auth/:provider', login.start);
 *   app.get('/auth/:provider/callback', login.callback);
 *
 *   // (b) One call that registers both routes for you (batteries included):
 *   mountOAuthLogin(app, { oauth, cookie: { secret } });
 *
 * `mountOAuthLogin` is just sugar over `oauthLogin` + `app.get/post`. Both
 * take the same config; `mode: 'api'` swaps the browser redirect for a
 * JSON flow (POST) for mobile / SPA / CLI clients.
 *
 * The security (PKCE / state / nonce / `iss` / COAT binding) lives in the
 * core; the adapter only moves the session and shapes the response. The
 * callback route MUST sit at the `callback` template given to createOAuth.
 */
import { parseCookies, serialiseCookie, serialiseDeleteCookie } from '@exortek/shared/cookie';
import { isFunction, isObject } from '@exortek/shared/predicates';

import { normalizeLoginConfig, startLogin, completeLogin, handoff } from './core.js';

/**
 * Build the `{ start, callback }` Express handlers for the login flow —
 * mount them on your own routes. `method` tells you which verb to use
 * (`'get'` for web, `'post'` for api), and `loginPath` / `callbackPath`
 * are the defaults if you want them.
 *
 * @param {import('./core.js').LoginConfig} config
 * @returns {{ start: Function, callback: Function, method: 'get'|'post', loginPath: string, callbackPath: string }}
 */
export function oauthLogin(config) {
  const cfg = normalizeLoginConfig(config);
  const api = cfg.mode === 'api';
  return {
    start: api ? apiStart(cfg) : webStart(cfg),
    callback: api ? apiCallback(cfg) : webCallback(cfg),
    method: api ? 'post' : 'get',
    loginPath: cfg.loginPath,
    callbackPath: cfg.callbackPath,
  };
}

/**
 * Register the login + callback routes on an Express app / router — the
 * one-call form of {@link oauthLogin}.
 *
 * @param {any} app
 * @param {import('./core.js').LoginConfig} config
 */
export function mountOAuthLogin(app, config) {
  const { start, callback, method, loginPath, callbackPath } = oauthLogin(config);
  app[method](callbackPath, callback);
  app[method](loginPath, start);
}

// WEB (browser redirect + cookie / store)

function webStart(cfg) {
  return async function start(req, res, next) {
    try {
      const { authorizeUrl, setCookie } = await startLogin(cfg, req.params.provider, {});
      if (setCookie) {
        res.setHeader('Set-Cookie', serialiseCookie(setCookie.name, setCookie.value, setCookie.options));
      }
      res.redirect(authorizeUrl);
    } catch (err) {
      onError(cfg, req, res, err, next);
    }
  };
}

function webCallback(cfg) {
  return async function callback(req, res, next) {
    try {
      const cookies = parseCookies(req.headers.cookie);
      const { result, clearCookie } = await completeLogin(cfg, req.params.provider, req.query, {
        cookieValue: cookies[cfg.cookieName],
      });
      if (clearCookie) {
        res.setHeader('Set-Cookie', serialiseDeleteCookie(clearCookie, { path: cfg.cookieOptions.path }));
      }
      handoff(cfg, req, res, result, next);
    } catch (err) {
      onError(cfg, req, res, err, next);
    }
  };
}

// API (JSON, client-held session)

function apiStart(cfg) {
  return async function start(req, res, next) {
    try {
      const { authorizeUrl, session, warnings } = await startLogin(cfg, req.params.provider, {});
      res.json({ authorizeUrl, session, warnings });
    } catch (err) {
      onError(cfg, req, res, err, next);
    }
  };
}

function apiCallback(cfg) {
  return async function callback(req, res, next) {
    try {
      const body = isObject(req.body) ? req.body : {};
      const { session, ...query } = body;
      const { result } = await completeLogin(cfg, req.params.provider, query, { session });
      if (isFunction(cfg.onSuccess)) {
        return cfg.onSuccess({ req, res, ...result });
      }
      // Default: the client (a mobile app / SPA) receives the resolved
      // identity; a dev wanting the provider tokens returns them from
      // their own `onSuccess`.
      res.json({ user: result.user, warnings: result.warnings, provider: result.provider });
    } catch (err) {
      onError(cfg, req, res, err, next);
    }
  };
}

/**
 * @param {import('./core.js').ResolvedLoginConfig} cfg
 * @param {any} req @param {any} res @param {unknown} err @param {Function} next
 */
function onError(cfg, req, res, err, next) {
  if (isFunction(cfg.onError)) {
    return cfg.onError({ req, res, error: err });
  }
  next(err);
}
