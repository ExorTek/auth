/**
 * Fastify adapter for the `@exortek/oidc` relying-party login flow.
 *
 *   import { oidcLoginPlugin } from '@exortek/oidc/client/fastify';
 *
 *   await app.register(oidcLoginPlugin, {
 *     client,
 *     onSuccess: ({ reply, idToken, claims }) => reply.redirect('/'),
 *   });
 *
 * `fastify-plugin` is an OPTIONAL peer — pulled from `@exortek/shared`'s
 * bundled `fastifyPlugin` so the routes register at the app's top level.
 * API / SPA / mobile clients can call `client.authorize` /
 * `client.handleCallback` directly instead.
 */
import { fastifyPlugin } from '@exortek/shared/fastify-plugin';
import { parseCookies, serialiseCookie, serialiseDeleteCookie } from '@exortek/shared/cookie';
import { isFunction, isObject } from '@exortek/shared/predicates';

const DEFAULT_COOKIE = 'oidc_flow';

/**
 * @param {any} fastify
 * @param {import('./express.js').OidcLoginConfig & { loginPath?: string, callbackPath?: string }} options
 */
async function oidcLoginPluginFn(fastify, options) {
  if (!isObject(options) || !isObject(options.client) || !isFunction(options.client.authorize)) {
    throw new TypeError('oidcLoginPlugin requires { client } from createClient()');
  }
  const client = options.client;
  const cookieName = options.cookie?.name ?? DEFAULT_COOKIE;
  const cookieOptions = {
    httpOnly: true,
    sameSite: options.cookie?.sameSite ?? 'lax',
    secure: options.cookie?.secure ?? true,
    path: options.cookie?.path ?? '/',
    maxAge: options.cookie?.maxAge ?? 600,
  };

  fastify.route({
    method: 'GET',
    url: options.loginPath ?? '/login',
    async handler(request, reply) {
      const authorizeOptions = isFunction(options.authorizeOptions) ? options.authorizeOptions(request) : {};
      const { url, session } = await client.authorize(authorizeOptions);
      reply.header('set-cookie', serialiseCookie(cookieName, session, cookieOptions));
      reply.redirect(url);
    },
  });

  fastify.route({
    method: 'GET',
    url: options.callbackPath ?? '/callback',
    async handler(request, reply) {
      const session = parseCookies(request.headers.cookie)[cookieName];
      const result = await client.handleCallback(request.query, { session });
      reply.header('set-cookie', serialiseDeleteCookie(cookieName, { path: cookieOptions.path }));
      if (isFunction(options.onSuccess)) {
        return options.onSuccess({ request, reply, ...result });
      }
      reply.status(204).send();
    },
  });
}

export const oidcLoginPlugin = fastifyPlugin(oidcLoginPluginFn, {
  fastify: '>=4',
  name: '@exortek/oidc-login',
});
