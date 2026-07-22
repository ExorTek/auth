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
 * Plain plugin (no fastify-plugin wrapper). The preHandler applies
 * within the plugin's scope only — mount under a prefix / register in
 * a scoped route group to control which routes require an API key.
 */

import { normalizeOptions, runApiKey } from './core.js';

export async function apiKeyPlugin(app, options) {
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
