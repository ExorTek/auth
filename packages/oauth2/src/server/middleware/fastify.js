/**
 * Fastify adapter for the `@exortek/oauth2` authorization server.
 *
 *   import Fastify from 'fastify';
 *   import { createServer, jwtIssuer } from '@exortek/oauth2/server';
 *   import { oauth2ServerPlugin } from '@exortek/oauth2/server/fastify';
 *
 *   const app = Fastify();
 *   await app.register(oauth2ServerPlugin, { server: createServer({ ... }) });
 *
 * `fastify-plugin` is an OPTIONAL peer — pulled from `@exortek/shared`'s
 * bundled `fastifyPlugin` so the routes register at the app's top level
 * (no encapsulation) without a hard dependency on the npm package.
 */
import { fastifyPlugin } from '@exortek/shared/fastify-plugin';
import { isFunction, isObject } from '@exortek/shared/predicates';

/**
 * @typedef {Object} OAuth2ServerPluginOptions
 * @property {ReturnType<import('../index.js').createServer>} server
 * @property {string} [basePath='']
 */

/**
 * @param {any} fastify
 * @param {OAuth2ServerPluginOptions} options
 */
async function oauth2ServerPluginFn(fastify, options) {
  const server = options?.server;
  if (!isObject(server) || !isFunction(server.token)) {
    throw new TypeError('oauth2ServerPlugin requires { server } from createServer()');
  }
  const base = options.basePath ?? '';

  const route = (method, path, handler) => {
    fastify.route({
      method,
      url: `${base}${path}`,
      handler: adapt(handler),
    });
  };

  route('GET', '/.well-known/oauth-authorization-server', server.metadata);
  route('GET', '/.well-known/openid-configuration', server.metadata);
  route('GET', '/authorize', server.authorize);
  route('POST', '/token', server.token);
  route('POST', '/revoke', server.revoke);
  route('POST', '/introspect', server.introspect);
  route('POST', '/par', server.par);
  route('POST', '/device_authorization', server.deviceAuthorization);
}

/**
 * @param {(raw: import('../request.js').RawRequest) => Promise<import('../response.js').ServerResponse>} handler
 */
function adapt(handler) {
  return async function oauth2FastifyRoute(request, reply) {
    const out = await handler({
      method: request.method,
      url: request.url,
      headers: request.headers,
      query: request.query,
      body: request.body,
      clientCertificate: readPeerCertificate(request),
    });
    reply.status(out.status);
    for (const [name, value] of Object.entries(out.headers)) {
      reply.header(name, value);
    }
    // The core has already serialized the body (JSON string / empty);
    // send it as-is so Fastify doesn't re-encode it.
    reply.send(out.body);
  };
}

/**
 * @param {any} request
 * @returns {object | undefined}
 */
function readPeerCertificate(request) {
  const socket = request.socket ?? request.raw?.socket;
  if (socket && isFunction(socket.getPeerCertificate)) {
    const cert = socket.getPeerCertificate(true);
    return cert && Object.keys(cert).length > 0 ? cert : undefined;
  }
  return undefined;
}

export const oauth2ServerPlugin = fastifyPlugin(oauth2ServerPluginFn, {
  fastify: '>=4',
  name: '@exortek/oauth2-server',
});
