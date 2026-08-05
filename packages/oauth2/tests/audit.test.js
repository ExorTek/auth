// Regression tests for the pre-1.0 audit (REPORT.md), one describe per batch.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync } from 'node:crypto';

import { sign as jwtSign } from '@exortek/jwt';

import { jwtIssuer } from '../src/server/index.js';
import { createParStore, createAuthCodeStore } from '../src/server/stores.js';
import { mountOAuth2Server } from '../src/server/middleware/express.js';
import {
  buildServer,
  getAuthorizationCode,
  dpopClient,
  assertionClient,
  post,
  get,
  body,
  ISSUER,
} from './helpers/server.js';

const DEVICE = 'urn:ietf:params:oauth:grant-type:device_code';
const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const CC = 'client_credentials';
const JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

// BATCH 1 — authorization gaps

test('C5: a client not registered for a grant is refused (device / exchange)', async () => {
  const { server } = buildServer({
    clients: [
      {
        clientId: 'app',
        clientSecret: 'app-secret-value-strong',
        tokenEndpointAuthMethod: 'client_secret_post',
        redirectUris: ['https://x/cb'],
        grantTypes: ['client_credentials'],
      },
    ],
    grants: ['client_credentials', DEVICE, EXCHANGE],
  });
  const dev = body(
    await server.token(
      post({ grant_type: DEVICE, device_code: 'x', client_id: 'app', client_secret: 'app-secret-value-strong' }),
    ),
  );
  assert.equal(dev.error, 'unauthorized_client');
  const ex = body(
    await server.token(
      post({
        grant_type: EXCHANGE,
        client_id: 'app',
        client_secret: 'app-secret-value-strong',
        subject_token: 'x',
        subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      }),
    ),
  );
  assert.equal(ex.error, 'unauthorized_client');
});

test("C2: a client cannot introspect another client's refresh token", async () => {
  const clients = [
    {
      clientId: 'app',
      clientSecret: 'app-secret-value-strong',
      tokenEndpointAuthMethod: 'client_secret_post',
      redirectUris: ['https://app.example.com/cb'],
      grantTypes: ['authorization_code', 'refresh_token'],
      scope: ['read'],
    },
    {
      clientId: 'spy',
      clientSecret: 'spy-secret-value-strong',
      tokenEndpointAuthMethod: 'client_secret_post',
      redirectUris: ['https://spy.example.com/cb'],
      grantTypes: ['client_credentials'],
    },
  ];
  const { server } = buildServer({ clients, grants: ['authorization_code', 'refresh_token', 'client_credentials'] });

  const { code, pkce, redirectUri } = await getAuthorizationCode(server, { scope: 'read' });
  const tok = body(
    await server.token(
      post({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: 'app',
        client_secret: 'app-secret-value-strong',
        code_verifier: pkce.codeVerifier,
      }),
    ),
  );

  // The owner sees it active…
  const own = body(
    await server.introspect(
      post({ token: tok.refresh_token, client_id: 'app', client_secret: 'app-secret-value-strong' }),
    ),
  );
  assert.equal(own.active, true);
  // …a different client sees inactive (no oracle).
  const other = body(
    await server.introspect(
      post({ token: tok.refresh_token, client_id: 'spy', client_secret: 'spy-secret-value-strong' }),
    ),
  );
  assert.equal(other.active, false);
});

test('C2: allowCrossClient re-enables resource-server introspection', async () => {
  const clients = [
    {
      clientId: 'app',
      clientSecret: 'app-secret-value-strong',
      tokenEndpointAuthMethod: 'client_secret_post',
      redirectUris: ['https://app.example.com/cb'],
      grantTypes: ['authorization_code', 'refresh_token'],
      scope: ['read'],
    },
    {
      clientId: 'rs',
      clientSecret: 'rs-secret-value-strong',
      tokenEndpointAuthMethod: 'client_secret_post',
      redirectUris: ['https://rs.example.com/cb'],
      grantTypes: ['client_credentials'],
    },
  ];
  const { server } = buildServer({
    clients,
    grants: ['authorization_code', 'refresh_token', 'client_credentials'],
    introspection: { allowCrossClient: true },
  });
  const { code, pkce, redirectUri } = await getAuthorizationCode(server, { scope: 'read' });
  const tok = body(
    await server.token(
      post({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: 'app',
        client_secret: 'app-secret-value-strong',
        code_verifier: pkce.codeVerifier,
      }),
    ),
  );
  const seen = body(
    await server.introspect(
      post({ token: tok.refresh_token, client_id: 'rs', client_secret: 'rs-secret-value-strong' }),
    ),
  );
  assert.equal(seen.active, true);
});

test('C4: a client registered PAR-required is refused on the front channel', async () => {
  const { server } = buildServer({
    clients: [
      {
        clientId: 'app',
        clientSecret: 'app-secret-value-strong',
        tokenEndpointAuthMethod: 'client_secret_post',
        redirectUris: ['https://app.example.com/cb'],
        requirePushedAuthorizationRequests: true,
      },
    ],
  });
  const res = await server.authorize({
    method: 'GET',
    url:
      '/authorize?' +
      new URLSearchParams({
        client_id: 'app',
        redirect_uri: 'https://app.example.com/cb',
        response_type: 'code',
        state: 's',
        code_challenge: 'a'.repeat(43),
        code_challenge_method: 'S256',
      }),
  });
  assert.equal(new URL(res.headers.location).searchParams.get('error'), 'invalid_request');
});

test('C4: a scope outside the client registration is invalid_scope', async () => {
  const { server } = buildServer({
    clients: [
      {
        clientId: 'app',
        clientSecret: 'app-secret-value-strong',
        tokenEndpointAuthMethod: 'client_secret_post',
        redirectUris: ['https://app.example.com/cb'],
        scope: ['read'],
      },
    ],
    scopes: ['read', 'write'],
  });
  const res = await server.authorize({
    method: 'GET',
    url:
      '/authorize?' +
      new URLSearchParams({
        client_id: 'app',
        redirect_uri: 'https://app.example.com/cb',
        response_type: 'code',
        state: 's',
        scope: 'write',
        code_challenge: 'a'.repeat(43),
        code_challenge_method: 'S256',
      }),
  });
  assert.equal(new URL(res.headers.location).searchParams.get('error'), 'invalid_scope');
});

test('C4: a client not permitted the code response type is unauthorized_client', async () => {
  const { server } = buildServer({
    clients: [
      {
        clientId: 'app',
        clientSecret: 'app-secret-value-strong',
        tokenEndpointAuthMethod: 'client_secret_post',
        redirectUris: ['https://app.example.com/cb'],
        responseTypes: [],
      },
    ],
  });
  const res = await server.authorize({
    method: 'GET',
    url:
      '/authorize?' +
      new URLSearchParams({
        client_id: 'app',
        redirect_uri: 'https://app.example.com/cb',
        response_type: 'code',
        state: 's',
        code_challenge: 'a'.repeat(43),
        code_challenge_method: 'S256',
      }),
  });
  assert.equal(new URL(res.headers.location).searchParams.get('error'), 'unauthorized_client');
});

// BATCH 2 — replay / confusion windows

test('C7: a token not typed at+jwt does not introspect as an active access token', async () => {
  const kp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const issuer = jwtIssuer({ signingKey: kp.privateKey, verificationKey: kp.publicKey, alg: 'ES256' });
  // An id_token / assertion signed with the SAME key must not pass as an
  // access token just because the signature and issuer check out.
  const idToken = await jwtSign({ sub: 'user-1' }, kp.privateKey, {
    alg: 'ES256',
    typ: 'JWT',
    issuer: ISSUER,
    audience: 'app',
    expiresIn: 60,
  });
  assert.equal((await issuer.introspect(idToken, { issuer: ISSUER })).active, false);
  // A genuine at+jwt from the same issuer is active.
  const at = await issuer.issue({ subject: 'user-1', clientId: 'app' }, { issuer: ISSUER });
  assert.equal((await issuer.introspect(at.accessToken, { issuer: ISSUER })).active, true);
});

test('C6: a client assertion without exp is refused', async () => {
  const client = await assertionClient('pk');
  const { server } = buildServer({
    clients: [
      {
        clientId: 'pk',
        tokenEndpointAuthMethod: 'private_key_jwt',
        jwks: { keys: [client.jwk] },
        redirectUris: ['https://x/cb'],
        grantTypes: [CC],
        scope: ['api'],
      },
    ],
    grants: [CC],
  });
  const noExp = await jwtSign({ iss: 'pk', sub: 'pk', aud: ISSUER, jti: 'ne1' }, client.kp.privateKey, {
    alg: 'ES256',
    header: { kid: 'k1' },
  });
  const res = body(
    await server.token(
      post({ grant_type: CC, client_assertion_type: JWT_BEARER, client_assertion: noExp, scope: 'api' }),
    ),
  );
  assert.equal(res.error, 'invalid_client');
});

test('C6: a client assertion with an over-long lifetime is refused', async () => {
  const client = await assertionClient('pk');
  const { server } = buildServer({
    clients: [
      {
        clientId: 'pk',
        tokenEndpointAuthMethod: 'private_key_jwt',
        jwks: { keys: [client.jwk] },
        redirectUris: ['https://x/cb'],
        grantTypes: [CC],
        scope: ['api'],
      },
    ],
    grants: [CC],
  });
  // One hour ahead — beyond the accepted 5-minute assertion lifetime.
  const longExp = await jwtSign(
    { iss: 'pk', sub: 'pk', aud: ISSUER, jti: 'le1', exp: Math.floor(Date.now() / 1000) + 3600 },
    client.kp.privateKey,
    { alg: 'ES256', header: { kid: 'k1' } },
  );
  const res = body(
    await server.token(
      post({ grant_type: CC, client_assertion_type: JWT_BEARER, client_assertion: longExp, scope: 'api' }),
    ),
  );
  assert.equal(res.error, 'invalid_client');
});

test('C3: a PAR DPoP proof must bind to the PAR endpoint, not the token endpoint', async () => {
  const dpop = await dpopClient();
  const { server } = buildServer({
    clients: [
      {
        clientId: 'app',
        clientSecret: 'app-secret-value-strong',
        tokenEndpointAuthMethod: 'client_secret_post',
        redirectUris: ['https://app.example.com/cb'],
        grantTypes: ['authorization_code'],
        scope: ['read'],
      },
    ],
  });
  const params = {
    client_id: 'app',
    client_secret: 'app-secret-value-strong',
    response_type: 'code',
    redirect_uri: 'https://app.example.com/cb',
    code_challenge: 'a'.repeat(43),
    code_challenge_method: 'S256',
  };
  // Proof bound to the token endpoint → htu mismatch at PAR.
  const wrong = body(await server.par(post(params, { dpop: await dpop.proof('POST', `${ISSUER}/token`) })));
  assert.equal(wrong.error, 'invalid_dpop_proof');
  // Proof bound to the PAR endpoint → accepted, pre-binds dpop_jkt.
  const ok = await server.par(post(params, { dpop: await dpop.proof('POST', `${ISSUER}/par`) }));
  assert.equal(ok.status, 201);
});

// BATCH 3 — store contract + eviction

// A Promise-returning (Redis-shaped) store must drive a full PAR round-trip;
// before D3 the handler spread a Promise and every PAR silently produced {}.
test('D3: async (Promise-returning) PAR / auth-code stores drive a full flow', async () => {
  const par = createParStore();
  const authCode = createAuthCodeStore();
  // Wrap every method so it returns a Promise, mimicking a Redis backend.
  const asyncify = store =>
    Object.fromEntries(Object.entries(store).map(([k, fn]) => [k, async (...args) => fn(...args)]));
  const { server } = buildServer({
    security: { par: { required: true } },
    stores: { par: asyncify(par), authCode: asyncify(authCode) },
  });

  const pushed = body(
    await server.par(
      post({
        client_id: 'app',
        client_secret: 's3cret-value-strong',
        redirect_uri: 'https://app.example.com/cb',
        response_type: 'code',
        code_challenge: 'a'.repeat(43),
        code_challenge_method: 'S256',
      }),
    ),
  );
  assert.ok(pushed.request_uri.startsWith('urn:ietf:params:oauth:request_uri:'));
  const authed = await server.authorize(get('/authorize', { request_uri: pushed.request_uri }));
  assert.ok(new URL(authed.headers.location).searchParams.get('code'));
});

test('P1: a refresh token past refreshTokenTtl is no longer valid', async () => {
  const { server } = buildServer({
    security: { refreshTokenTtl: 1 }, // 1 ms — expired by the time it is presented
  });
  const { code, pkce, redirectUri } = await getAuthorizationCode(server, { scope: 'read' });
  const tok = body(
    await server.token(
      post({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: 'app',
        client_secret: 's3cret-value-strong',
        code_verifier: pkce.codeVerifier,
      }),
    ),
  );
  await new Promise(r => setTimeout(r, 5));
  const res = body(
    await server.token(
      post({
        grant_type: 'refresh_token',
        refresh_token: tok.refresh_token,
        client_id: 'app',
        client_secret: 's3cret-value-strong',
      }),
    ),
  );
  assert.equal(res.error, 'invalid_grant');
});

// BATCH 4 — correctness polish + dead surface

test('C9: an unknown response_mode is rejected (redirectable invalid_request)', async () => {
  const { server } = buildServer();
  const res = await server.authorize(
    get('/authorize', {
      client_id: 'app',
      redirect_uri: 'https://app.example.com/cb',
      response_type: 'code',
      state: 's',
      response_mode: 'fragment',
      code_challenge: 'a'.repeat(43),
      code_challenge_method: 'S256',
    }),
  );
  assert.equal(new URL(res.headers.location).searchParams.get('error'), 'invalid_request');
});

test('C9: metadata advertises response_modes_supported per jarm config', async () => {
  const plain = body(await buildServer().server.metadata(get('/.well-known/oauth-authorization-server', {})));
  assert.deepEqual(plain.response_modes_supported, ['query']);
  // JARM is advertised only when fully configured (a signing key is present);
  // an under-configured jarm can't sign, so it is treated as absent.
  const jarmKp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jarm = body(
    await buildServer({ jarm: { alg: 'ES256', signingKey: jarmKp.privateKey } }).server.metadata(get('/x', {})),
  );
  assert.deepEqual(jarm.response_modes_supported, ['query', 'jwt']);
  // A jarm config without a signing key does not advertise jwt mode.
  const under = body(await buildServer({ jarm: { alg: 'ES256' } }).server.metadata(get('/x', {})));
  assert.deepEqual(under.response_modes_supported, ['query']);
});

test('D1: revoke rejects an unsupported token_type_hint (unsupported_token_type)', async () => {
  const { server } = buildServer();
  const res = body(
    await server.revoke(
      post({ token: 'whatever', token_type_hint: 'bogus', client_id: 'app', client_secret: 's3cret-value-strong' }),
    ),
  );
  assert.equal(res.error, 'unsupported_token_type');
});

test('D1: a DPoP nonce challenge is issued, then the retry succeeds', async () => {
  const dpop = await dpopClient();
  const { server } = buildServer({ security: { dpop: { nonce: true } } });
  const { code, pkce, redirectUri } = await getAuthorizationCode(server, { scope: 'read' });

  // First attempt carries a proof but no nonce → use_dpop_nonce + header.
  const challenge = await server.token(
    post(
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: 'app',
        client_secret: 's3cret-value-strong',
        code_verifier: pkce.codeVerifier,
      },
      { dpop: await dpop.proof('POST', `${ISSUER}/token`) },
    ),
  );
  assert.equal(body(challenge).error, 'use_dpop_nonce');
  const nonce = challenge.headers['dpop-nonce'];
  assert.ok(nonce, 'a DPoP-Nonce header is supplied');

  // The code was NOT consumed on the challenge — retry with the nonce.
  const ok = body(
    await server.token(
      post(
        {
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
          client_id: 'app',
          client_secret: 's3cret-value-strong',
          code_verifier: pkce.codeVerifier,
        },
        { dpop: await dpop.proof('POST', `${ISSUER}/token`, nonce) },
      ),
    ),
  );
  assert.ok(ok.access_token);
  assert.equal(ok.token_type, 'DPoP');
});

test('D5: the express adapter mounts at the configured endpoint paths', () => {
  /** @type {Array<[string, string]>} */
  const routes = [];
  const app = {
    get: p => routes.push(['GET', p]),
    post: p => routes.push(['POST', p]),
  };
  const { server } = buildServer({ endpoints: { token: 'https://as.example.com/oauth/token' } });
  mountOAuth2Server(app, server);
  assert.ok(
    routes.some(r => r[0] === 'POST' && r[1] === '/oauth/token'),
    'token endpoint mounts at its configured path',
  );
});

test('D2: an injected store missing a method is rejected at createServer', () => {
  assert.throws(
    () => buildServer({ stores: { par: { save() {} } } }),
    err => {
      assert.match(err.message, /stores\.par/);
      return true;
    },
  );
});

// BATCH 5 — performance + additions

test('§4.1: verifyDpopForResource binds a proof to the token (ath + cnf.jkt)', async () => {
  const { verifyDpopForResource, _clearDpopReplayCache } = await import('../src/server/security/dpop.js');
  const { sign: jwsSign } = await import('@exortek/jws');
  const { createHash } = await import('node:crypto');
  _clearDpopReplayCache();
  const dpop = await dpopClient();
  const accessToken = 'the-opaque-or-jwt-access-token';
  const ath = createHash('sha256').update(accessToken).digest('base64url');
  const rsUrl = 'https://rs.example.com/resource';

  // A proof with no ath → rejected at the resource server.
  await assert.rejects(
    verifyDpopForResource(await dpop.proof('GET', rsUrl), { htm: 'GET', htu: rsUrl, accessToken, cnfJkt: dpop.jkt }),
    /ath/,
  );

  // Correct ath + matching cnf.jkt → accepted.
  const bound = await jwsSign(
    { jti: `${Math.random()}`, htm: 'GET', htu: rsUrl, iat: Math.floor(Date.now() / 1000), ath },
    dpop.kp.privateKey,
    { alg: 'ES256', header: { typ: 'dpop+jwt', jwk: dpop.jwk } },
  );
  const res = await verifyDpopForResource(bound, { htm: 'GET', htu: rsUrl, accessToken, cnfJkt: dpop.jkt });
  assert.equal(res.jkt, dpop.jkt);
});

test('§4.4: the authorization request is accepted over POST (form_post)', async () => {
  const { server } = buildServer();
  const res = await server.authorize(
    post({
      client_id: 'app',
      redirect_uri: 'https://app.example.com/cb',
      response_type: 'code',
      state: 's',
      code_challenge: 'a'.repeat(43),
      code_challenge_method: 'S256',
    }),
  );
  assert.ok(new URL(res.headers.location).searchParams.get('code'), 'a code is issued for a POST authorize');
});
