/**
 * Express adapter for the RP social-login flow. Serves either a
 * browser-redirect flow (`mode: 'web'`, the default) or a JSON flow for
 * mobile / SPA / CLI clients (`mode: 'api'`) — same `createOAuth` core,
 * different transport.
 *
 *   import { mountOAuthLogin } from '@exortek/oauth2/express';
 *
 *   // Web: GET /auth/:provider → redirect, GET /auth/:provider/callback → user
 *   mountOAuthLogin(app, { oauth, cookie: { secret }, onSuccess: ({ req, res, user }) => {...} });
 *
 *   // API: POST /auth/:provider → { authorizeUrl, session }, POST callback → { user, tokens }
 *   mountOAuthLogin(app, { oauth, mode: 'api', secret });
 *
 * The security (PKCE / state / nonce / `iss` / COAT binding) lives in the
 * core; the adapter only moves the session and shapes the response. The
 * `callbackPath` MUST equal the `callback` template given to createOAuth.
 */
import { parseCookies, serialiseCookie, serialiseDeleteCookie } from '@exortek/shared/cookie';
import { isFunction, isObject } from '@exortek/shared/predicates';

import { normalizeLoginConfig, startLogin, completeLogin, handoff } from './core.js';

/**
 * Register the login + callback routes on an Express app / router.
 *
 * @param {any} app
 * @param {import('./core.js').LoginConfig} config
 */
export function mountOAuthLogin(app, config) {
  const cfg = normalizeLoginConfig(config);
  if (cfg.mode === 'api') {
    app.post(cfg.callbackPath, apiCallback(cfg));
    app.post(cfg.loginPath, apiStart(cfg));
  } else {
    app.get(cfg.callbackPath, webCallback(cfg));
    app.get(cfg.loginPath, webStart(cfg));
  }
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
