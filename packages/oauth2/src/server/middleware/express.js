/**
 * Express adapter for the `@exortek/oauth2` authorization server.
 *
 *   import express from 'express';
 *   import { createServer, jwtIssuer } from '@exortek/oauth2/server';
 *   import { mountOAuth2Server } from '@exortek/oauth2/server/express';
 *
 *   const app = express();
 *   app.use(express.urlencoded({ extended: false }));
 *   const oauth = createServer({ ...  });
 *   mountOAuth2Server(app, oauth);
 *
 * The server core is framework-agnostic: it consumes a normalized
 * `{ method, url, headers, query, body }` request and returns a
 * `{ status, headers, body }` response. This adapter only translates
 * to/from Express's native `req`/`res`.
 */
import { isFunction, isString } from '@exortek/shared/predicates';

import { errorResponse } from '../response.js';

/**
 * Wrap a single server handler as an Express `(req, res)` handler.
 *
 * @param {(raw: import('../request.js').RawRequest) => Promise<import('../response.js').ServerResponse>} handler
 * @returns {(req: any, res: any) => Promise<void>}
 */
export function expressHandler(handler) {
  return async function oauth2ExpressHandler(req, res) {
    // An unexpected throw is masked as `server_error` at the boundary
    // rather than surfaced to Express's default handler (which would leak
    // a stack trace in development).
    let out;
    try {
      out = await handler(toRawRequest(req));
    } catch (err) {
      out = errorResponse(err);
    }
    res.status(out.status);
    for (const [name, value] of Object.entries(out.headers)) {
      res.setHeader(name, value);
    }
    res.send(out.body);
  };
}

/**
 * Register every authorization-server endpoint on an Express app. The
 * discovery document is served from both well-known paths.
 *
 * @param {any} app                              an Express application / router
 * @param {ReturnType<import('../index.js').createServer>} server
 * @param {{ basePath?: string }} [options]
 */
export function mountOAuth2Server(app, server, options = {}) {
  const base = options.basePath ?? '';
  // Mount each endpoint at the path portion of its configured URL so a
  // custom `endpoints` override stays consistent with the advertised
  // metadata and the DPoP `htu` the core validates against.
  const p = endpointPaths(server);
  app.get(`${base}/.well-known/oauth-authorization-server`, expressHandler(server.metadata));
  app.get(`${base}/.well-known/openid-configuration`, expressHandler(server.metadata));
  app.get(`${base}${p.authorization}`, expressHandler(server.authorize));
  app.post(`${base}${p.token}`, expressHandler(server.token));
  app.post(`${base}${p.revocation}`, expressHandler(server.revoke));
  app.post(`${base}${p.introspection}`, expressHandler(server.introspect));
  app.post(`${base}${p.par}`, expressHandler(server.par));
  app.post(`${base}${p.deviceAuthorization}`, expressHandler(server.deviceAuthorization));
}

/**
 * The path portion of each configured endpoint URL, so the adapter mounts
 * exactly where the metadata says the endpoint lives.
 *
 * @param {ReturnType<import('../index.js').createServer>} server
 * @returns {Record<string, string>}
 */
export function endpointPaths(server) {
  const endpoints = server?._config?.endpoints ?? {};
  /** @type {Record<string, string>} */
  const out = {};
  for (const [key, url] of Object.entries(endpoints)) {
    out[key] = pathOf(url);
  }
  return out;
}

/**
 * @param {unknown} url
 * @returns {string}
 */
function pathOf(url) {
  if (!isString(url)) {
    return '/';
  }
  try {
    return new URL(url).pathname;
  } catch {
    return url.startsWith('/') ? url : `/${url}`;
  }
}

/**
 * @param {any} req
 * @returns {import('../request.js').RawRequest}
 */
function toRawRequest(req) {
  return {
    method: req.method,
    url: req.originalUrl ?? req.url,
    headers: req.headers,
    // Express parses these when the app mounts `express.urlencoded()` /
    // `express.json()`; the core also handles a raw string body.
    query: req.query,
    body: req.body,
    clientCertificate: readPeerCertificate(req),
  };
}

/**
 * mTLS client cert (RFC 8705). Available on a TLS socket when the server
 * was configured with `requestCert: true`.
 *
 * @param {any} req
 * @returns {object | undefined}
 */
function readPeerCertificate(req) {
  const socket = req.socket ?? req.connection;
  if (socket && isFunction(socket.getPeerCertificate)) {
    const cert = socket.getPeerCertificate(true);
    return cert && Object.keys(cert).length > 0 ? cert : undefined;
  }
  return undefined;
}
