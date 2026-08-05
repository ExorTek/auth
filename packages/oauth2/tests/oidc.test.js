/**
 * OpenID Provider behaviour (id_token issuance + OIDC discovery) and the
 * 1.0.0 hardening additions (JAR exp/replay, device-endpoint client auth,
 * DPoP-aware introspection token_type). All hermetic — local keys, in-memory
 * stores.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync } from 'node:crypto';

import { verify as jwtVerify, sign as jwtSign } from '@exortek/jwt';

import {
  buildServer,
  getAuthorizationCode,
  dpopClient,
  assertionClient,
  post,
  form,
  body,
  ISSUER,
} from './helpers/server.js';
import { tokenHash } from '../src/internal/id-token.js';

const DEVICE = 'urn:ietf:params:oauth:grant-type:device_code';

/** Build a server that is an OpenID Provider, plus the id_token keypair. */
function buildOidcServer(overrides = {}) {
  const idKp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { server, asKp } = buildServer({
    clients: [
      {
        clientId: 'app',
        clientSecret: 's3cret-value-strong',
        tokenEndpointAuthMethod: 'client_secret_post',
        redirectUris: ['https://app.example.com/cb'],
        grantTypes: ['authorization_code', 'refresh_token'],
        scope: ['read', 'write', 'openid'],
      },
    ],
    authenticateUser: () => ({ subject: 'user-1', authTime: 1710000000 }),
    oidc: { idToken: { signingKey: idKp.privateKey, alg: 'ES256' } },
    ...overrides,
  });
  return { server, asKp, idKp };
}

test('OIDC: an openid-scoped code grant returns a verifiable id_token', async () => {
  const { server, idKp } = buildOidcServer();
  const { code, pkce, redirectUri } = await getAuthorizationCode(server, {
    scope: 'openid read',
    extra: { nonce: 'n-123' },
  });

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

  assert.ok(tok.id_token, 'id_token present');
  const { payload } = await jwtVerify(tok.id_token, idKp.publicKey, {
    alg: ['ES256'],
    issuer: ISSUER,
    audience: 'app',
  });
  assert.equal(payload.sub, 'user-1');
  assert.equal(payload.nonce, 'n-123');
  assert.equal(payload.auth_time, 1710000000);
  // at_hash binds the paired access token (OIDC Core §3.1.3.6).
  assert.equal(payload.at_hash, tokenHash(tok.access_token, 'ES256'));
});

test('OIDC: a non-openid grant gets no id_token even on an OpenID Provider', async () => {
  const { server } = buildOidcServer();
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
  assert.equal(tok.id_token, undefined);
});

test('OIDC: metadata advertises the OpenID Provider fields', async () => {
  const { server } = buildOidcServer();
  assert.equal(server._config.oidcEnabled, true);
  const doc = body(server.metadata());
  assert.deepEqual(doc.subject_types_supported, ['public']);
  assert.deepEqual(doc.id_token_signing_alg_values_supported, ['ES256']);
  assert.ok(doc.scopes_supported.includes('openid'));
});

test('a plain OAuth 2.1 AS issues no id_token and hides OIDC metadata', async () => {
  const { server } = buildServer(); // no `oidc`
  assert.equal(server._config.oidcEnabled, false);
  const doc = body(server.metadata());
  assert.equal(doc.subject_types_supported, undefined);
  assert.equal(doc.id_token_signing_alg_values_supported, undefined);

  const { code, pkce, redirectUri } = await getAuthorizationCode(server, { scope: 'openid read' });
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
  assert.equal(tok.id_token, undefined);
});

// HARDENING

test('S3: a JAR request object without exp is rejected', async () => {
  const client = await assertionClient('jarapp');
  const { server } = buildServer({
    clients: [
      {
        clientId: 'jarapp',
        tokenEndpointAuthMethod: 'none',
        jwks: { keys: [client.jwk] },
        redirectUris: ['https://app/cb'],
      },
    ],
  });

  // No `exp` on the request object → invalid_request.
  const requestObject = await jwtSign(
    {
      client_id: 'jarapp',
      redirect_uri: 'https://app/cb',
      response_type: 'code',
      code_challenge: 'a'.repeat(43),
      code_challenge_method: 'S256',
      aud: ISSUER,
    },
    client.kp.privateKey,
    { alg: 'ES256', header: { kid: 'k1' } },
  );
  const res = await server.authorize({
    method: 'GET',
    url: `/authorize?${form({ client_id: 'jarapp', request: requestObject })}`,
  });
  // No trusted redirect yet (params came from the object) → direct JSON error.
  assert.equal(body(res).error, 'invalid_request');
});

test('S4: the device endpoint authenticates a confidential client', async () => {
  const { server } = buildServer({
    clients: [
      {
        clientId: 'dev',
        clientSecret: 'dev-secret-strong-value',
        tokenEndpointAuthMethod: 'client_secret_post',
        redirectUris: ['https://dev/cb'],
        grantTypes: [DEVICE],
      },
    ],
    grants: [DEVICE],
    device: { interval: 0 },
  });

  // Missing secret → invalid_client (was silently accepted before).
  const noAuth = await server.deviceAuthorization(post({ client_id: 'dev' }));
  assert.equal(body(noAuth).error, 'invalid_client');

  // With the secret it succeeds.
  const ok = body(
    await server.deviceAuthorization(post({ client_id: 'dev', client_secret: 'dev-secret-strong-value' })),
  );
  assert.ok(ok.device_code);
});

test('M1: introspection reports token_type DPoP for a sender-constrained token', async () => {
  const { server } = buildServer({
    clients: [
      {
        clientId: 'app',
        clientSecret: 's3cret-value-strong',
        tokenEndpointAuthMethod: 'client_secret_post',
        redirectUris: ['https://app.example.com/cb'],
        dpopBoundAccessTokens: true,
      },
    ],
  });
  const dpop = await dpopClient();
  const { code, pkce, redirectUri } = await getAuthorizationCode(server);
  const tok = body(
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
        { dpop: await dpop.proof('POST', `${ISSUER}/token`) },
      ),
    ),
  );
  assert.equal(tok.token_type, 'DPoP');

  const introspected = body(
    await server.introspect(post({ token: tok.access_token, client_id: 'app', client_secret: 's3cret-value-strong' })),
  );
  assert.equal(introspected.active, true);
  assert.equal(introspected.token_type, 'DPoP');
});
