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
 * The plugin bypasses Fastify's encapsulation so the `preHandler` hook
 * and the `req.apiKey` decorator apply to routes in the parent scope.
 * Register inside a scoped `app.register(async scope => …)` block to
 * control which route group needs an API key.
 */

import { fastifyPlugin } from '@exortek/shared/fastify-plugin';

import { normalizeOptions, runApiKey } from './core.js';

export const apiKeyPlugin = fastifyPlugin(
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
  },
  { name: '@exortek/apikey' },
);
