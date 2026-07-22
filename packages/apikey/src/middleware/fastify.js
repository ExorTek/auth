/**
 * Fastify plugin for `@exortek/apikey`.
 *
 *   import Fastify from 'fastify';
 *   import { apiKeyPlugin } from '@exortek/apikey/middleware/fastify';
 *   import { memoryStore } from '@exortek/apikey/stores';
 *
 *   const app = Fastify();
 *   await app.register(apiKeyPlugin, {
 *     store: memoryStore(),
 *     requiredScopes: ['read'],
 *     updateLastUsed: true,
 *   });
 *
 *   app.get('/v1/whoami', async req => req.apiKey);
 *
 * Wrapped with `fastify-plugin` so the `preHandler` hook and the
 * `req.apiKey` decorator escape encapsulation and apply to routes
 * registered as siblings in the parent scope. Register the plugin
 * inside a scoped `app.register(async scope => …)` block to control
 * which route group needs an API key — the usual Fastify pattern for
 * "protect only these routes with auth".
 *
 * `fastify-plugin` is an **optional peer** — install it with
 * `npm i fastify fastify-plugin` (or `yarn add`) alongside the fastify
 * runtime.  Not a hard dependency because Express-only consumers of
 * `@exortek/apikey` should not have to install it.
 */

import fp from 'fastify-plugin';

import { normalizeOptions, runApiKey } from './core.js';

async function apiKeyPluginFn(app, options) {
  const config = normalizeOptions(options);

  app.decorateRequest(config.attach, null);

  app.addHook('preHandler', async (req, reply) => {
    const ctx = {
      getHeader: name => req.headers?.[name],
      method: req.method,
      ip: req.ip,
      query: req.query,
    };
    const result = await runApiKey(ctx, config);
    if (result.response) {
      reply.code(result.response.status).send(result.response.body);
      return reply;
    }
    req[config.attach] = result.verifyResult;
    return undefined;
  });
}

export const apiKeyPlugin = fp(apiKeyPluginFn, {
  fastify: '4.x || 5.x',
  name: '@exortek/apikey',
});
