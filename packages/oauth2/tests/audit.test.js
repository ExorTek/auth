// Regression tests for the pre-1.0 audit (REPORT.md), one describe per batch.
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildServer, getAuthorizationCode, post, body } from './helpers/server.js';

const DEVICE = 'urn:ietf:params:oauth:grant-type:device_code';
const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';

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
