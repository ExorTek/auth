/**
 * Express adapter for the `@exortek/oidc` OpenID Provider add-ons.
 *
 *   import express from 'express';
 *   import { createProvider } from '@exortek/oidc/provider';
 *   import { mountOidcProvider } from '@exortek/oidc/provider/express';
 *
 *   const provider = createProvider({ ... });
 *   mountOidcProvider(app, provider);
 *
 * The provider handlers are framework-agnostic (`{ method, url, headers,
 * query } → { status, headers, body }`); this adapter only translates to and
 * from Express's native `req`/`res`, and mounts each endpoint at the path the
 * discovery document advertises.
 */
import { pathOf, providerRoutes } from './routes.js';

/**
 * Wrap a single provider handler as an Express `(req, res)` handler.
 *
 * @param {(raw: object) => (object | Promise<object>)} handler
 * @returns {(req: any, res: any) => Promise<void>}
 */
export function expressHandler(handler) {
  return async function oidcExpressHandler(req, res) {
    const out = await handler({
      method: req.method,
      url: req.originalUrl ?? req.url,
      headers: req.headers,
      query: req.query,
    });
    res.status(out.status);
    for (const [name, value] of Object.entries(out.headers)) {
      res.setHeader(name, value);
    }
    res.send(out.body);
  };
}

/**
 * Build the Express handlers for every endpoint the provider serves — mount
 * them on your own routes.
 *
 * @param {ReturnType<import('./index.js').createProvider>} provider
 * @returns {Record<string, { path: string, handler: Function }>}
 */
export function oidcProviderHandlers(provider) {
  /** @type {Record<string, { path: string, handler: Function }>} */
  const out = {};
  for (const [name, { path, handler }] of Object.entries(providerRoutes(provider))) {
    out[name] = { path, handler: expressHandler(handler) };
  }
  return out;
}

/**
 * Register every provider endpoint on an Express app / router — the one-call
 * form of {@link oidcProviderHandlers}. Discovery is served from the
 * well-known path; the rest at the path portion of their advertised URLs.
 *
 * @param {any} app
 * @param {ReturnType<import('./index.js').createProvider>} provider
 * @param {{ basePath?: string }} [options]
 */
export function mountOidcProvider(app, provider, options = {}) {
  const base = options.basePath ?? '';
  const routes = providerRoutes(provider);
  for (const { method, path, handler } of Object.values(routes)) {
    app[method.toLowerCase()](`${base}${pathOf(path)}`, expressHandler(handler));
  }
}
