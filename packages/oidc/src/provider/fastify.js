/**
 * Fastify adapter for the `@exortek/oidc` OpenID Provider add-ons.
 *
 *   import Fastify from 'fastify';
 *   import { createProvider } from '@exortek/oidc/provider';
 *   import { oidcProviderPlugin } from '@exortek/oidc/provider/fastify';
 *
 *   const app = Fastify();
 *   await app.register(oidcProviderPlugin, { provider: createProvider({ ... }) });
 *
 * `fastify-plugin` is an OPTIONAL peer — pulled from `@exortek/shared`'s
 * bundled `fastifyPlugin` so the routes register at the app's top level
 * without a hard dependency on the npm package.
 */
import { fastifyPlugin } from '@exortek/shared/fastify-plugin';
import { isFunction, isObject } from '@exortek/shared/predicates';

import { pathOf, providerRoutes } from './routes.js';

/**
 * Adapt a framework-agnostic provider handler to a Fastify route handler.
 *
 * @param {(raw: object) => (object | Promise<object>)} handler
 */
export function adapt(handler) {
  return async function oidcFastifyRoute(request, reply) {
    const out = await handler({
      method: request.method,
      url: request.url,
      headers: request.headers,
      query: request.query,
    });
    reply.status(out.status);
    for (const [name, value] of Object.entries(out.headers)) {
      reply.header(name, value);
    }
    reply.send(out.body);
  };
}

/**
 * @param {any} fastify
 * @param {{ provider: ReturnType<import('./index.js').createProvider>, basePath?: string }} options
 */
async function oidcProviderPluginFn(fastify, options) {
  const provider = options?.provider;
  if (!isObject(provider) || !isFunction(provider.discoveryHandler)) {
    throw new TypeError('oidcProviderPlugin requires { provider } from createProvider()');
  }
  const base = options.basePath ?? '';
  for (const { method, path, handler } of Object.values(providerRoutes(provider))) {
    fastify.route({ method, url: `${base}${pathOf(path)}`, handler: adapt(handler) });
  }
}

export const oidcProviderPlugin = fastifyPlugin(oidcProviderPluginFn, {
  fastify: '>=4',
  name: '@exortek/oidc-provider',
});
