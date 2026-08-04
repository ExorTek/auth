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
import { isFunction } from '@exortek/shared/predicates';

/**
 * Wrap a single server handler as an Express `(req, res)` handler.
 *
 * @param {(raw: import('../request.js').RawRequest) => Promise<import('../response.js').ServerResponse>} handler
 * @returns {(req: any, res: any, next: any) => Promise<void>}
 */
export function expressHandler(handler) {
  return async function oauth2ExpressHandler(req, res, next) {
    try {
      const out = await handler(toRawRequest(req));
      res.status(out.status);
      for (const [name, value] of Object.entries(out.headers)) {
        res.setHeader(name, value);
      }
      res.send(out.body);
    } catch (err) {
      next(err);
    }
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
  app.get(`${base}/.well-known/oauth-authorization-server`, expressHandler(server.metadata));
  app.get(`${base}/.well-known/openid-configuration`, expressHandler(server.metadata));
  app.get(`${base}/authorize`, expressHandler(server.authorize));
  app.post(`${base}/token`, expressHandler(server.token));
  app.post(`${base}/revoke`, expressHandler(server.revoke));
  app.post(`${base}/introspect`, expressHandler(server.introspect));
  app.post(`${base}/par`, expressHandler(server.par));
  app.post(`${base}/device_authorization`, expressHandler(server.deviceAuthorization));
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
