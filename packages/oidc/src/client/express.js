/**
 * Express adapter for the `@exortek/oidc` relying-party login flow.
 *
 *   import { mountOidcLogin } from '@exortek/oidc/client/express';
 *
 *   mountOidcLogin(app, {
 *     client,                       // from createClient(...)
 *     onSuccess: ({ res, idToken, claims, userinfo }) => { ... res.redirect('/'); },
 *   });
 *
 * A browser-redirect flow: `start` sends the user to the OP with the flow
 * session stashed in a short-lived cookie; `callback` reads it back, runs
 * `client.handleCallback`, and hands the result to `onSuccess`. API / SPA /
 * mobile clients can call `client.authorize` / `client.handleCallback`
 * directly instead.
 */
import { parseCookies, serialiseCookie, serialiseDeleteCookie } from '@exortek/shared/cookie';
import { isFunction, isObject } from '@exortek/shared/predicates';

const DEFAULT_COOKIE = 'oidc_flow';

/**
 * @typedef {object} OidcLoginConfig
 * @property {ReturnType<import('./index.js').createClient>} client
 * @property {{ name?: string, path?: string, maxAge?: number, secure?: boolean, sameSite?: string }} [cookie]
 * @property {(ctx: object) => unknown} [onSuccess]  called with `{ req, res, ...result }`; default 204.
 * @property {(ctx: { req: any, res: any, error: unknown }) => unknown} [onError]  default `next(error)`.
 * @property {(req: any) => object} [authorizeOptions]  per-request options passed to `client.authorize`.
 */

/**
 * Build the `{ start, callback }` Express handlers — mount them on your own
 * routes.
 *
 * @param {OidcLoginConfig} config
 * @returns {{ start: Function, callback: Function }}
 */
export function oidcLogin(config) {
  if (!isObject(config) || !isObject(config.client) || !isFunction(config.client.authorize)) {
    throw new TypeError('oidcLogin requires { client } from createClient()');
  }
  const client = config.client;
  const cookieName = config.cookie?.name ?? DEFAULT_COOKIE;
  const cookieOptions = {
    httpOnly: true,
    sameSite: config.cookie?.sameSite ?? 'lax',
    secure: config.cookie?.secure ?? true,
    path: config.cookie?.path ?? '/',
    maxAge: config.cookie?.maxAge ?? 600,
  };

  return {
    async start(req, res, next) {
      try {
        const options = isFunction(config.authorizeOptions) ? config.authorizeOptions(req) : {};
        const { url, session } = await client.authorize(options);
        res.setHeader('Set-Cookie', serialiseCookie(cookieName, session, cookieOptions));
        res.redirect(url);
      } catch (err) {
        onError(config, req, res, err, next);
      }
    },

    async callback(req, res, next) {
      try {
        const session = parseCookies(req.headers.cookie)[cookieName];
        const result = await client.handleCallback(req.query, { session });
        res.setHeader('Set-Cookie', serialiseDeleteCookie(cookieName, { path: cookieOptions.path }));
        if (isFunction(config.onSuccess)) {
          return config.onSuccess({ req, res, ...result });
        }
        res.status(204).end();
      } catch (err) {
        onError(config, req, res, err, next);
      }
    },
  };
}

/**
 * Register the login + callback routes on an Express app / router.
 *
 * @param {any} app
 * @param {OidcLoginConfig & { loginPath?: string, callbackPath?: string }} config
 */
export function mountOidcLogin(app, config) {
  const { start, callback } = oidcLogin(config);
  app.get(config.loginPath ?? '/login', start);
  app.get(config.callbackPath ?? '/callback', callback);
}

function onError(config, req, res, err, next) {
  if (isFunction(config.onError)) {
    return config.onError({ req, res, error: err });
  }
  if (isFunction(next)) {
    return next(err);
  }
  throw err;
}
