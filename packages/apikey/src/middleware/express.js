/**
 * Express adapter for `@exortek/apikey`.
 *
 *   import express from 'express';
 *   import { apiKeyMiddleware } from '@exortek/apikey/middleware/express';
 *   import { memoryStore } from '@exortek/apikey/stores';
 *
 *   const app = express();
 *   const store = memoryStore();
 *
 *   app.use('/v1', apiKeyMiddleware({
 *     store,
 *     requiredScopes: ['read'],
 *     updateLastUsed: true,
 *   }));
 *
 *   app.get('/v1/whoami', (req, res) => res.json(req.apiKey));
 */

import { normalizeOptions, runApiKey } from './core.js';

/**
 * @param {import('./core.js').ApiKeyMiddlewareOptions} options
 */
export function apiKeyMiddleware(options) {
  const config = normalizeOptions(options);
  return async function apikeyExpressMiddleware(req, res, next) {
    const ctx = {
      getHeader: name => req.headers?.[name],
      method: req.method,
      ip: req.ip,
      query: req.query,
    };
    let result;
    try {
      result = await runApiKey(ctx, config);
    } catch (err) {
      return next(err);
    }
    if (result.response) {
      res.status(result.response.status).json(result.response.body);
      return;
    }
    req[config.attach] = result.verifyResult;
    next();
  };
}
