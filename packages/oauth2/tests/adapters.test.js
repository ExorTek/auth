// Coverage for the framework adapters — the thin req/res translation layer
// around the framework-agnostic server core (audit §4.5).
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { expressHandler, mountOAuth2Server } from '../src/server/middleware/express.js';
import { oauth2ServerPlugin } from '../src/server/middleware/fastify.js';
import { buildServer } from './helpers/server.js';

/** A minimal Express `res` double. */
function fakeRes() {
  return {
    statusCode: undefined,
    headers: {},
    body: undefined,
    status(code) {
      this.statusCode = code;
      return this;
    },
    setHeader(name, value) {
      this.headers[name] = value;
    },
    send(body) {
      this.body = body;
    },
  };
}

test('express: a handler writes status, headers, and body onto res', async () => {
  const { server } = buildServer();
  const res = fakeRes();
  await expressHandler(server.metadata)(
    { method: 'GET', url: '/.well-known/oauth-authorization-server', headers: {} },
    res,
  );
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers['content-type'], 'application/json');
  assert.equal(JSON.parse(res.body).issuer, 'https://as.example.com');
});

test('express: an unexpected throw is masked as server_error, not leaked', async () => {
  const res = fakeRes();
  const boom = () => {
    throw new Error('internal detail that must not leak');
  };
  await expressHandler(boom)({ method: 'GET', url: '/x', headers: {} }, res);
  assert.equal(res.statusCode, 500);
  assert.equal(JSON.parse(res.body).error, 'server_error');
  assert.doesNotMatch(res.body, /internal detail/);
});

test('express: mountOAuth2Server registers every endpoint', () => {
  const routes = [];
  const app = { get: p => routes.push(['GET', p]), post: p => routes.push(['POST', p]) };
  const { server } = buildServer();
  mountOAuth2Server(app, server);
  const paths = routes.map(r => r[1]);
  for (const p of ['/authorize', '/token', '/revoke', '/introspect', '/par', '/device_authorization']) {
    assert.ok(paths.includes(p), `mounts ${p}`);
  }
});

test('fastify: the server plugin registers routes and drives one end-to-end', async () => {
  const routes = new Map();
  const fastify = {
    route({ method, url, handler }) {
      routes.set(`${method} ${url}`, handler);
    },
  };
  const { server } = buildServer();
  await oauth2ServerPlugin(fastify, { server });
  assert.ok(routes.has('GET /authorize'));
  assert.ok(routes.has('POST /token'));

  // Drive the metadata route through a fake reply.
  const reply = {
    statusCode: undefined,
    headers: {},
    body: undefined,
    status(code) {
      this.statusCode = code;
      return this;
    },
    header(name, value) {
      this.headers[name] = value;
    },
    send(body) {
      this.body = body;
    },
  };
  await routes.get('GET /.well-known/oauth-authorization-server')(
    { method: 'GET', url: '/.well-known/oauth-authorization-server', headers: {} },
    reply,
  );
  assert.equal(reply.statusCode, 200);
  assert.equal(JSON.parse(reply.body).issuer, 'https://as.example.com');
});

test('fastify: the server plugin requires a { server }', async () => {
  await assert.rejects(() => oauth2ServerPlugin({ route() {} }, {}), /createServer/);
});
