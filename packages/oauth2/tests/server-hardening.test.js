/**
 * Authorization-server hardening: the scope ceiling, dynamic-registration
 * limits, PAR integrity, mTLS chain checks, refresh / device lifetimes and
 * token-exchange subject checks. Each test reproduces an escalation or
 * bypass that used to succeed.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildServer, getAuthorizationCode, dpopClient, get, post, body, ISSUER } from './helpers/server.js';

// SCOPE CEILING

const WIDE_CLIENT = {
  clientId: 'wide',
  clientSecret: 's3cret-value-strong',
  tokenEndpointAuthMethod: 'client_secret_post',
  redirectUris: ['https://wide.example.com/cb'],
  grantTypes: ['authorization_code', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'],
  // Registers a scope the server never advertises.
  scope: ['read', 'admin'],
};

test('scope ceiling: authorize refuses a client scope the server does not advertise', async () => {
  const { server } = buildServer({ clients: [WIDE_CLIENT], scopes: ['read', 'write'] });
  const { res, code } = await getAuthorizationCode(server, {
    clientId: 'wide',
    redirectUri: 'https://wide.example.com/cb',
    scope: 'read admin',
  });
  assert.equal(code, null);
  assert.equal(new URL(res.headers.location).searchParams.get('error'), 'invalid_scope');
});

test('scope ceiling: client_credentials refuses, and never defaults to, an unadvertised scope', async () => {
  const { server } = buildServer({ clients: [WIDE_CLIENT], scopes: ['read', 'write'] });
  const creds = { client_id: 'wide', client_secret: 's3cret-value-strong' };

  const asked = await server.token(post({ grant_type: 'client_credentials', scope: 'admin', ...creds }));
  assert.equal(asked.status, 400);
  assert.equal(body(asked).error, 'invalid_scope');

  const implicit = body(await server.token(post({ grant_type: 'client_credentials', ...creds })));
  assert.equal(implicit.scope, 'read');
});

test('scope ceiling: device authorization validates the requested scope', async () => {
  const { server } = buildServer({
    clients: [WIDE_CLIENT],
    scopes: ['read', 'write'],
    grants: ['urn:ietf:params:oauth:grant-type:device_code'],
  });
  const res = await server.deviceAuthorization(
    post({ client_id: 'wide', client_secret: 's3cret-value-strong', scope: 'admin' }),
  );
  assert.equal(res.status, 400);
  assert.equal(body(res).error, 'invalid_scope');
});

// PAR

const PKCE_PARAMS = {
  redirect_uri: 'https://app.example.com/cb',
  response_type: 'code',
  code_challenge: 'a'.repeat(43),
  code_challenge_method: 'S256',
};

test('PAR: a forged _fromPar parameter does not satisfy a PAR requirement', async () => {
  const { server } = buildServer({ security: { par: { required: true } } });
  const res = await server.authorize(get('/authorize', { client_id: 'app', _fromPar: '1', ...PKCE_PARAMS }));
  const location = new URL(res.headers.location);
  assert.equal(location.searchParams.get('code'), null);
  assert.equal(location.searchParams.get('error'), 'invalid_request');
});

test('PAR: request_uri must be redeemed with the client_id that pushed it', async () => {
  const other = {
    clientId: 'other',
    clientSecret: 'other-secret-value-strong',
    tokenEndpointAuthMethod: 'client_secret_post',
    redirectUris: ['https://app.example.com/cb'],
  };
  const { server } = buildServer({
    clients: [
      {
        clientId: 'app',
        clientSecret: 's3cret-value-strong',
        tokenEndpointAuthMethod: 'client_secret_post',
        redirectUris: ['https://app.example.com/cb'],
      },
      other,
    ],
  });
  const pushed = body(
    await server.par(post({ client_id: 'app', client_secret: 's3cret-value-strong', ...PKCE_PARAMS })),
  );

  const missing = await server.authorize(get('/authorize', { request_uri: pushed.request_uri }));
  assert.equal(body(missing).error, 'invalid_request');

  const pushedAgain = body(
    await server.par(post({ client_id: 'app', client_secret: 's3cret-value-strong', ...PKCE_PARAMS })),
  );
  const mismatch = await server.authorize(
    get('/authorize', { client_id: 'other', request_uri: pushedAgain.request_uri }),
  );
  assert.equal(body(mismatch).error, 'invalid_request');
});

test('PAR: a pushed request object is verified at push time', async () => {
  const { server } = buildServer();
  const res = await server.par(post({ client_id: 'app', client_secret: 's3cret-value-strong', request: 'not.a.jwt' }));
  assert.equal(res.status, 400);
  assert.equal(body(res).error, 'invalid_request');
});

// mTLS (tls_client_auth)

const PKI_CLIENT = {
  clientId: 'pki',
  tokenEndpointAuthMethod: 'tls_client_auth',
  tlsClientAuthSubjectDn: 'CN=pki-client,O=Bank',
  redirectUris: ['https://x.example.com/cb'],
  grantTypes: ['client_credentials'],
  scope: ['read'],
};

function mtlsRequest(subject, authorized) {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: 'pki' }).toString(),
    clientCertificate: { raw: Buffer.from('der'), subject },
    clientCertificateAuthorized: authorized,
  };
}

test('tls_client_auth: an unverified certificate with a matching DN is refused', async () => {
  const { server } = buildServer({ clients: [PKI_CLIENT], grants: ['client_credentials'] });
  const res = await server.token(mtlsRequest({ CN: 'pki-client', O: 'Bank' }, false));
  assert.equal(res.status, 401);
  assert.equal(body(res).error, 'invalid_client');

  const ok = await server.token(mtlsRequest({ O: 'Bank', CN: 'pki-client' }, true));
  assert.equal(ok.status, 200);
});

test('tls_client_auth: DN values are compared structurally, not as joined strings', async () => {
  const { server } = buildServer({
    clients: [{ ...PKI_CLIENT, tlsClientAuthSubjectDn: 'CN=foo\\,O=Bank' }],
    grants: ['client_credentials'],
  });
  // Joined naively this subject renders as "CN=foo,O=Bank" too.
  const forged = await server.token(mtlsRequest({ CN: 'foo', O: 'Bank' }, true));
  assert.equal(forged.status, 401);

  const real = await server.token(mtlsRequest({ CN: 'foo,O=Bank' }, true));
  assert.equal(real.status, 200);
});

test('express adapter passes socket.authorized through', async () => {
  const { server } = buildServer({ clients: [PKI_CLIENT], grants: ['client_credentials'] });
  const { expressHandler } = await import('../src/server/middleware/express.js');
  const handle = expressHandler(server.token);
  const statuses = [];
  for (const authorized of [false, true]) {
    const socket = {
      authorized,
      getPeerCertificate: () => ({ raw: Buffer.from('der'), subject: { CN: 'pki-client', O: 'Bank' } }),
    };
    const req = {
      method: 'POST',
      url: '/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: { grant_type: 'client_credentials', client_id: 'pki' },
      query: {},
      socket,
    };
    const res = {
      status(code) {
        statuses.push(code);
        return this;
      },
      setHeader() {},
      send() {},
    };
    await handle(req, res);
  }
  assert.deepEqual(statuses, [401, 200]);
});

// REFRESH ROTATION

async function issueRefresh(server) {
  const { code, pkce, redirectUri } = await getAuthorizationCode(server, { scope: 'read write' });
  return body(
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
}

function refresh(server, token, extra = {}) {
  return server.token(
    post({
      grant_type: 'refresh_token',
      refresh_token: token,
      client_id: 'app',
      client_secret: 's3cret-value-strong',
      ...extra,
    }),
  );
}

test('refresh: a rotated token keeps the family expiry', async () => {
  const { server } = buildServer({ security: { refreshTokenTtl: 80 } });
  const first = await issueRefresh(server);
  const rotated = body(await refresh(server, first.refresh_token));
  assert.ok(rotated.refresh_token);

  const record = await server._config.stores.refresh.get(rotated.refresh_token);
  assert.equal(typeof record.expiresAt, 'number');

  await new Promise(r => setTimeout(r, 100));
  assert.equal(body(await refresh(server, rotated.refresh_token)).error, 'invalid_grant');
});

test('refresh: two simultaneous redemptions cannot fork the family', async () => {
  const { server } = buildServer();
  const first = await issueRefresh(server);
  const results = (await Promise.all([refresh(server, first.refresh_token), refresh(server, first.refresh_token)])).map(
    body,
  );
  const winners = results.filter(r => r.refresh_token);
  assert.equal(winners.length, 1);
  assert.equal(results.find(r => !r.refresh_token).error, 'invalid_grant');
  // The race is treated as reuse: the winner's successor is burned too.
  assert.equal(body(await refresh(server, winners[0].refresh_token)).error, 'invalid_grant');
});

test('refresh: the memory store evicts expired tokens in the background', async () => {
  const { createRefreshStore } = await import('../src/server/stores.js');
  const store = createRefreshStore({ sweepIntervalMs: 10 });
  await store.save({ token: 'r1', familyId: 'f1', clientId: 'app', scope: [], expiresAt: Date.now() + 5 });
  await new Promise(r => setTimeout(r, 40));
  assert.equal(await store.get('r1'), null);
  await store.revokeFamily('f1');
  assert.equal(await store.get('r1'), null);
});

test('refresh: a narrowed request does not narrow the successor refresh token', async () => {
  const { server } = buildServer();
  const first = await issueRefresh(server);
  const narrowed = body(await refresh(server, first.refresh_token, { scope: 'read' }));
  assert.equal(narrowed.scope, 'read');
  const next = body(await refresh(server, narrowed.refresh_token, { scope: 'write' }));
  assert.equal(next.scope, 'write');
});

// TOKEN EXCHANGE

const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

function exchangeServer(extra = {}) {
  const svc = id => ({
    clientId: id,
    clientSecret: `${id}-secret-value-strong`,
    tokenEndpointAuthMethod: 'client_secret_post',
    redirectUris: ['https://x.example.com/cb'],
    grantTypes: ['client_credentials', EXCHANGE],
    scope: ['api'],
  });
  return buildServer({
    clients: [svc('alice'), svc('mallory')],
    grants: ['client_credentials', EXCHANGE],
    scopes: ['api'],
    tokenExchange: { audiences: ['https://downstream.example.com'] },
    ...extra,
  });
}

const creds = id => ({ client_id: id, client_secret: `${id}-secret-value-strong` });

async function ccToken(server, id, headers = {}) {
  return body(await server.token(post({ grant_type: 'client_credentials', scope: 'api', ...creds(id) }, headers)));
}

function exchange(server, id, subjectToken, extra = {}, headers = {}) {
  return server.token(
    post(
      {
        grant_type: EXCHANGE,
        subject_token: subjectToken,
        subject_token_type: ACCESS_TOKEN_TYPE,
        ...creds(id),
        ...extra,
      },
      headers,
    ),
  );
}

test('token exchange: a token issued to another client cannot be exchanged', async () => {
  const { server } = exchangeServer();
  const alice = await ccToken(server, 'alice');
  const res = await exchange(server, 'mallory', alice.access_token);
  assert.equal(res.status, 400);
  assert.equal(body(res).error, 'invalid_grant');

  assert.equal((await exchange(server, 'alice', alice.access_token)).status, 200);
});

test('token exchange: a DPoP-bound subject token needs the same key', async () => {
  const { server } = exchangeServer();
  const dpop = await dpopClient();
  const htu = `${ISSUER}/token`;
  const bound = await ccToken(server, 'alice', { dpop: await dpop.proof('POST', htu) });
  assert.equal(bound.token_type, 'DPoP');

  const stripped = await exchange(server, 'alice', bound.access_token);
  assert.equal(body(stripped).error, 'invalid_grant');

  const proven = await exchange(server, 'alice', bound.access_token, {}, { dpop: await dpop.proof('POST', htu) });
  assert.equal(proven.status, 200);
});

test('token exchange: the target audience must be allowlisted', async () => {
  const { server } = exchangeServer();
  const alice = await ccToken(server, 'alice');
  const res = await exchange(server, 'alice', alice.access_token, { audience: 'https://evil.example.com' });
  assert.equal(body(res).error, 'invalid_target');
  const ok = await exchange(server, 'alice', alice.access_token, { resource: 'https://downstream.example.com' });
  assert.equal(ok.status, 200);
});

test('token exchange: a prior actor chain nests under the new act', async () => {
  const { server } = exchangeServer();
  const alice = await ccToken(server, 'alice');
  const once = body(await exchange(server, 'alice', alice.access_token));
  const twice = body(await exchange(server, 'alice', once.access_token));
  const claims = JSON.parse(Buffer.from(twice.access_token.split('.')[1], 'base64url').toString());
  assert.deepEqual(claims.act, { sub: 'alice', act: { sub: 'alice' } });
});

// CERTIFICATE BINDING

test('refresh and device grants keep mTLS certificate binding', async () => {
  const der = Buffer.from('device-cert-der');
  const { createHash } = await import('node:crypto');
  const thumb = createHash('sha256').update(der).digest('base64url');
  const DEVICE = 'urn:ietf:params:oauth:grant-type:device_code';
  const { server } = buildServer({
    clients: [
      {
        clientId: 'mtls',
        tokenEndpointAuthMethod: 'self_signed_tls_client_auth',
        certificateThumbprint: thumb,
        redirectUris: ['https://x.example.com/cb'],
        grantTypes: [DEVICE, 'refresh_token'],
        scope: ['read'],
      },
    ],
    grants: [DEVICE, 'refresh_token'],
  });
  const call = (handler, params) =>
    handler({
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: 'mtls', ...params }).toString(),
      clientCertificate: { raw: der },
    });
  const cnfOf = tok => JSON.parse(Buffer.from(tok.split('.')[1], 'base64url').toString()).cnf;

  const da = body(await call(server.deviceAuthorization, { scope: 'read' }));
  await server.device.approve(da.user_code, { subject: 'user-1' });
  const tok = body(await call(server.token, { grant_type: DEVICE, device_code: da.device_code }));
  assert.equal(cnfOf(tok.access_token)['x5t#S256'], thumb);

  const refreshed = body(await call(server.token, { grant_type: 'refresh_token', refresh_token: tok.refresh_token }));
  assert.equal(cnfOf(refreshed.access_token)['x5t#S256'], thumb);
});
