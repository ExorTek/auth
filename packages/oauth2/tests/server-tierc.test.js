import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, generateKeyPairSync } from 'node:crypto';

import { sign as jwtSign, verify as jwtVerify } from '@exortek/jwt';
import { encode as b64url } from '@exortek/shared/base64url';

import { buildServer, assertionClient, post, form, body, ISSUER } from './helpers/server.js';

const CC = 'client_credentials';
const DEVICE = 'urn:ietf:params:oauth:grant-type:device_code';
const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

test('client_credentials issues a token with no refresh (RFC 6749 §4.4)', async () => {
  const { server } = buildServer({
    clients: [
      {
        clientId: 'svc',
        clientSecret: 'svc-secret-value-strong',
        tokenEndpointAuthMethod: 'client_secret_post',
        redirectUris: ['https://x/cb'],
        grantTypes: [CC],
        scope: ['api'],
      },
    ],
    grants: [CC],
  });
  const tok = body(
    await server.token(
      post({ grant_type: CC, client_id: 'svc', client_secret: 'svc-secret-value-strong', scope: 'api' }),
    ),
  );
  assert.ok(tok.access_token);
  assert.equal(tok.refresh_token, undefined);
});

test('a public client cannot use client_credentials', async () => {
  const { server } = buildServer({
    clients: [{ clientId: 'pub', tokenEndpointAuthMethod: 'none', redirectUris: ['https://x/cb'], grantTypes: [CC] }],
    grants: [CC],
  });
  const res = body(await server.token(post({ grant_type: CC, client_id: 'pub' })));
  assert.equal(res.error, 'unauthorized_client');
});

test('private_key_jwt client auth with assertion replay defense (RFC 7523, threat #19)', async () => {
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

  const ok = await server.token(
    post({
      grant_type: CC,
      client_assertion_type: JWT_BEARER,
      client_assertion: await client.assertion('j1'),
      scope: 'api',
    }),
  );
  assert.equal(ok.status, 200);

  // Same jti again → replay refused.
  const replay = body(
    await server.token(
      post({
        grant_type: CC,
        client_assertion_type: JWT_BEARER,
        client_assertion: await client.assertion('j1'),
        scope: 'api',
      }),
    ),
  );
  assert.equal(replay.error, 'invalid_client');

  // Wrong audience (not the issuer identifier) → refused.
  const wrongAud = body(
    await server.token(
      post({
        grant_type: CC,
        client_assertion_type: JWT_BEARER,
        client_assertion: await client.assertion('j2', 'https://as.example.com/token'),
        scope: 'api',
      }),
    ),
  );
  assert.equal(wrongAud.error, 'invalid_client');
});

test('client_secret_jwt client auth (HS256)', async () => {
  const secret = '0123456789abcdef0123456789abcdef';
  const { server } = buildServer({
    clients: [
      {
        clientId: 'hs',
        tokenEndpointAuthMethod: 'client_secret_jwt',
        clientSecret: secret,
        redirectUris: ['https://x/cb'],
        grantTypes: [CC],
        scope: ['api'],
      },
    ],
    grants: [CC],
  });
  const now = Math.floor(Date.now() / 1000);
  const assertion = await jwtSign(
    { iss: 'hs', sub: 'hs', aud: ISSUER, jti: 'h1', exp: now + 60 },
    Buffer.from(secret, 'utf8'),
    { alg: 'HS256' },
  );
  const res = await server.token(
    post({ grant_type: CC, client_assertion_type: JWT_BEARER, client_assertion: assertion, scope: 'api' }),
  );
  assert.equal(res.status, 200);
});

test('mTLS self_signed client auth binds a certificate-bound token (RFC 8705)', async () => {
  const der = Buffer.from('test-certificate-der-bytes');
  const thumb = b64url(createHash('sha256').update(der).digest());
  const { server, asKp } = buildServer({
    clients: [
      {
        clientId: 'mtls',
        tokenEndpointAuthMethod: 'self_signed_tls_client_auth',
        certificateThumbprint: thumb,
        redirectUris: ['https://x/cb'],
        grantTypes: [CC],
        scope: ['api'],
      },
    ],
    grants: [CC],
  });

  const req = {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ grant_type: CC, client_id: 'mtls', scope: 'api' }),
    clientCertificate: { raw: der },
  };
  const tok = body(await server.token(req));
  const { payload } = await jwtVerify(tok.access_token, asKp.publicKey, { alg: ['ES256'], issuer: ISSUER });
  assert.equal(payload.cnf['x5t#S256'], thumb);

  // A different certificate is rejected.
  const wrong = body(await server.token({ ...req, clientCertificate: { raw: Buffer.from('other') } }));
  assert.equal(wrong.error, 'invalid_client');
});

test('device authorization grant: pending → approved → single redeem (RFC 8628)', async () => {
  const { server } = buildServer({
    clients: [
      {
        clientId: 'dev',
        tokenEndpointAuthMethod: 'none',
        redirectUris: ['https://x/cb'],
        grantTypes: [DEVICE, 'refresh_token'],
      },
    ],
    grants: [DEVICE, 'refresh_token'],
    device: { interval: 0 },
  });

  const da = body(await server.deviceAuthorization(post({ client_id: 'dev' })));
  assert.match(da.user_code, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
  assert.ok(da.device_code);

  const pending = body(await server.token(post({ grant_type: DEVICE, device_code: da.device_code, client_id: 'dev' })));
  assert.equal(pending.error, 'authorization_pending');

  await server.device.approve(da.user_code, { subject: 'user-42' });
  const approved = body(
    await server.token(post({ grant_type: DEVICE, device_code: da.device_code, client_id: 'dev' })),
  );
  assert.ok(approved.access_token);

  const reRedeem = body(
    await server.token(post({ grant_type: DEVICE, device_code: da.device_code, client_id: 'dev' })),
  );
  assert.equal(reRedeem.error, 'invalid_grant');
});

test('device authorization: user denial surfaces access_denied', async () => {
  const { server } = buildServer({
    clients: [
      { clientId: 'dev', tokenEndpointAuthMethod: 'none', redirectUris: ['https://x/cb'], grantTypes: [DEVICE] },
    ],
    grants: [DEVICE],
    device: { interval: 0 },
  });
  const da = body(await server.deviceAuthorization(post({ client_id: 'dev' })));
  await server.device.deny(da.user_code);
  const denied = body(await server.token(post({ grant_type: DEVICE, device_code: da.device_code, client_id: 'dev' })));
  assert.equal(denied.error, 'access_denied');
});

test('token exchange delegates a subject token to a new audience (RFC 8693)', async () => {
  const client = await assertionClient('pk');
  const { server, asKp } = buildServer({
    clients: [
      {
        clientId: 'pk',
        tokenEndpointAuthMethod: 'private_key_jwt',
        jwks: { keys: [client.jwk] },
        redirectUris: ['https://x/cb'],
        grantTypes: [CC, EXCHANGE],
        scope: ['api'],
      },
    ],
    grants: [CC, EXCHANGE],
  });

  const subjectTok = body(
    await server.token(
      post({
        grant_type: CC,
        client_assertion_type: JWT_BEARER,
        client_assertion: await client.assertion('s1'),
        scope: 'api',
      }),
    ),
  );

  const exchanged = body(
    await server.token(
      post({
        grant_type: EXCHANGE,
        client_assertion_type: JWT_BEARER,
        client_assertion: await client.assertion('s2'),
        subject_token: subjectTok.access_token,
        subject_token_type: ACCESS_TOKEN_TYPE,
        resource: 'https://downstream.example.com',
      }),
    ),
  );
  assert.equal(exchanged.issued_token_type, ACCESS_TOKEN_TYPE);
  const { payload } = await jwtVerify(exchanged.access_token, asKp.publicKey, { alg: ['ES256'], issuer: ISSUER });
  assert.equal(payload.aud, 'https://downstream.example.com');
  assert.deepEqual(payload.act, { sub: 'pk' });
});

test('JAR request object + JARM signed response (RFC 9101)', async () => {
  const client = await assertionClient('jarapp');
  const jarmKp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { server } = buildServer({
    clients: [
      {
        clientId: 'jarapp',
        tokenEndpointAuthMethod: 'none',
        jwks: { keys: [client.jwk] },
        redirectUris: ['https://app/cb'],
      },
    ],
    jarm: { signingKey: jarmKp.privateKey, alg: 'ES256' },
  });

  const now = Math.floor(Date.now() / 1000);
  const requestObject = await jwtSign(
    {
      client_id: 'jarapp',
      redirect_uri: 'https://app/cb',
      response_type: 'code',
      response_mode: 'jwt',
      state: 'st-1',
      code_challenge: 'a'.repeat(43),
      code_challenge_method: 'S256',
      aud: ISSUER,
      exp: now + 60,
    },
    client.kp.privateKey,
    { alg: 'ES256', header: { kid: 'k1' } },
  );

  const res = await server.authorize({
    method: 'GET',
    url: `/authorize?${form({ client_id: 'jarapp', request: requestObject })}`,
  });
  const responseJwt = new URL(res.headers.location).searchParams.get('response');
  const { payload } = await jwtVerify(responseJwt, jarmKp.publicKey, {
    alg: ['ES256'],
    issuer: ISSUER,
    audience: 'jarapp',
  });
  assert.ok(payload.code);
  assert.equal(payload.state, 'st-1');
  assert.equal(payload.iss, ISSUER);
});

test('a confidential client cannot authenticate with the wrong method', async () => {
  const { server } = buildServer({
    clients: [
      {
        clientId: 'app',
        clientSecret: 'app-secret-value-strong',
        tokenEndpointAuthMethod: 'client_secret_basic',
        redirectUris: ['https://x/cb'],
        grantTypes: [CC],
        scope: ['api'],
      },
    ],
    grants: [CC],
  });
  // Registered basic, presenting post → refused.
  const res = body(
    await server.token(
      post({ grant_type: CC, client_id: 'app', client_secret: 'app-secret-value-strong', scope: 'api' }),
    ),
  );
  assert.equal(res.error, 'invalid_client');
});
