/**
 * Authorization-server hardening: the scope ceiling, dynamic-registration
 * limits, PAR integrity, mTLS chain checks, refresh / device lifetimes and
 * token-exchange subject checks. Each test reproduces an escalation or
 * bypass that used to succeed.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildServer, getAuthorizationCode, post, body } from './helpers/server.js';

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
