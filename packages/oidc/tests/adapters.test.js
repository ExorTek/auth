import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import Fastify from 'fastify';

import { createClient, createProvider } from '../src/index.js';
import { mountOidcProvider } from '../src/provider/express.js';
import { oidcProviderPlugin } from '../src/provider/fastify.js';
import { oidcLoginPlugin } from '../src/client/fastify.js';
import { makeSigner, startStubAS } from './helpers/oidc.js';

const ISSUER = 'https://auth.example.com';
const CLIENT_ID = 'test-client';

/** @type {Array<() => Promise<unknown>>} */
const cleanups = [];
afterEach(async () => {
  while (cleanups.length) {
    await cleanups.pop()();
  }
});

async function providerFor(extra = {}) {
  const signer = await makeSigner();
  return createProvider({
    issuer: ISSUER,
    signing: { key: signer.privateJwk, alg: signer.alg, kid: signer.kid },
    jwks: [signer.publicJwk],
    endpoints: { authorization: '/authorize', token: '/token' },
    userinfo: {
      resolve: t => (t === 'ok' ? { sub: 'u1', scope: 'openid email', claims: { email: 'u@e.com' } } : null),
    },
    logout: { postLogoutRedirectUris: ['https://app.example.com/out'] },
    session: {},
    ...extra,
  });
}

describe('provider fastify plugin', () => {
  it('serves discovery, jwks, userinfo, end_session and check_session', async () => {
    const app = Fastify();
    cleanups.push(() => app.close());
    await app.register(oidcProviderPlugin, { provider: await providerFor() });
    await app.ready();

    const disco = await app.inject({ method: 'GET', url: '/.well-known/openid-configuration' });
    assert.equal(disco.statusCode, 200);
    assert.equal(JSON.parse(disco.body).issuer, ISSUER);

    const jwks = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
    assert.equal(JSON.parse(jwks.body).keys.length, 1);

    const ui = await app.inject({ method: 'GET', url: '/userinfo', headers: { authorization: 'Bearer ok' } });
    assert.equal(ui.statusCode, 200);
    assert.equal(JSON.parse(ui.body).email, 'u@e.com');

    const ui401 = await app.inject({ method: 'GET', url: '/userinfo' });
    assert.equal(ui401.statusCode, 401);

    const cs = await app.inject({ method: 'GET', url: '/check_session' });
    assert.match(cs.headers['content-type'], /text\/html/);
  });
});

describe('provider express mount', () => {
  it('registers a route per advertised endpoint and the handler responds', async () => {
    const routes = [];
    const app = {
      get: (path, handler) => routes.push({ path, handler }),
    };
    mountOidcProvider(app, await providerFor());
    const paths = routes.map(r => r.path);
    assert.ok(paths.includes('/.well-known/openid-configuration'));
    assert.ok(paths.includes('/.well-known/jwks.json'));
    assert.ok(paths.includes('/userinfo'));
    assert.ok(paths.includes('/end_session'));
    assert.ok(paths.includes('/check_session'));

    // Invoke the discovery handler through a mock res.
    const discovery = routes.find(r => r.path === '/.well-known/openid-configuration').handler;
    const rec = mockRes();
    await discovery({ method: 'GET', url: '/.well-known/openid-configuration', headers: {}, query: {} }, rec);
    assert.equal(rec.statusCode, 200);
    assert.equal(JSON.parse(rec.body).issuer, ISSUER);
  });
});

describe('client fastify login plugin', () => {
  it('runs a browser login round-trip against a stub OP', async () => {
    const signer = await makeSigner();
    const holder = { idToken: '' };
    const as = await startStubAS({
      publicJwks: [signer.publicJwk],
      token: () => ({ access_token: 'at', token_type: 'Bearer', id_token: holder.idToken }),
      userinfo: () => ({ sub: 'user-1', email: 'u@e.com' }),
    });
    cleanups.push(as.close);

    const client = createClient({
      issuer: as.issuer,
      clientId: CLIENT_ID,
      redirectUri: 'https://app.example.com/callback',
      jwksOptions: { allowInsecure: true },
    });

    let captured;
    const app = Fastify();
    cleanups.push(() => app.close());
    await app.register(oidcLoginPlugin, {
      client,
      cookie: { secure: false },
      onSuccess: ({ reply, claims }) => {
        captured = claims;
        reply.status(200).send('ok');
      },
    });
    await app.ready();

    const start = await app.inject({ method: 'GET', url: '/login' });
    assert.equal(start.statusCode, 302);
    const authUrl = new URL(start.headers.location);
    const nonce = authUrl.searchParams.get('nonce');
    const state = authUrl.searchParams.get('state');
    const session = cookieValue(start.headers['set-cookie'], 'oidc_flow');

    holder.idToken = await signer.mint({ iss: as.issuer, sub: 'user-1', aud: CLIENT_ID, nonce });

    const cb = await app.inject({
      method: 'GET',
      url: `/callback?code=abc&state=${encodeURIComponent(state)}`,
      headers: { cookie: `oidc_flow=${session}` },
    });
    assert.equal(cb.statusCode, 200);
    assert.equal(captured.sub, 'user-1');
  });
});

function mockRes() {
  return {
    statusCode: 0,
    headers: {},
    body: '',
    status(code) {
      this.statusCode = code;
      return this;
    },
    setHeader(name, value) {
      this.headers[name] = value;
    },
    send(body) {
      this.body = body;
      return this;
    },
  };
}

/** @param {string|string[]|undefined} setCookie @param {string} name */
function cookieValue(setCookie, name) {
  const list = Array.isArray(setCookie) ? setCookie : [setCookie];
  for (const raw of list) {
    if (typeof raw === 'string' && raw.startsWith(`${name}=`)) {
      return raw.slice(name.length + 1).split(';')[0];
    }
  }
  return undefined;
}
