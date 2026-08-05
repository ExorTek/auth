/**
 * Dynamic Client Registration (RFC 7591). Opt-in, initial-access-token gated
 * by default; a registered client is immediately usable for a code flow.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync } from 'node:crypto';

import { createServer, jwtIssuer, createClientRegistry } from '../src/server/index.js';
import { getAuthorizationCode, post, body, ISSUER } from './helpers/server.js';

const IAT = 'initial-access-token-strong-value';

function buildRegistrationServer(registration) {
  const asKp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const server = createServer({
    issuer: ISSUER,
    clients: createClientRegistry([]), // empty, dynamic
    tokens: jwtIssuer({ signingKey: asKp.privateKey, verificationKey: asKp.publicKey, alg: 'ES256' }),
    authenticateUser: () => ({ subject: 'user-1' }),
    scopes: ['read', 'write'],
    registration,
  });
  return { server, asKp };
}

/** JSON POST body (RFC 7591 §3.1 uses application/json). */
function jsonPost(obj, headers = {}) {
  return { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(obj) };
}

test('registration is disabled unless configured', async () => {
  const asKp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const server = createServer({
    issuer: ISSUER,
    clients: createClientRegistry([]),
    tokens: jwtIssuer({ signingKey: asKp.privateKey, alg: 'ES256' }),
    authenticateUser: () => ({ subject: 'u' }),
  });
  assert.equal(server._config.registrationEnabled, false);
  assert.equal(body(server.metadata()).registration_endpoint, undefined);
});

test('registration without an initial access token is refused (secure default)', async () => {
  const { server } = buildRegistrationServer({ initialAccessToken: IAT });
  const res = await server.register(jsonPost({ redirect_uris: ['https://c/cb'] }));
  assert.equal(res.status, 401);
  assert.equal(body(res).error, 'invalid_client');
});

test('registration mints a confidential client that can complete a code flow', async () => {
  const { server } = buildRegistrationServer({ initialAccessToken: IAT });
  assert.equal(server._config.registrationEnabled, true);
  assert.equal(body(server.metadata()).registration_endpoint, `${ISSUER}/register`);

  const reg = body(
    await server.register(
      jsonPost(
        {
          redirect_uris: ['https://c.example.com/cb'],
          token_endpoint_auth_method: 'client_secret_post',
          grant_types: ['authorization_code'],
          client_name: 'My App',
          scope: 'read',
        },
        { authorization: `Bearer ${IAT}` },
      ),
    ),
  );
  assert.ok(reg.client_id);
  assert.ok(reg.client_secret);
  assert.equal(reg.client_secret_expires_at, 0);
  assert.equal(reg.client_name, 'My App');

  // The freshly-registered client works end to end.
  const { code, pkce, redirectUri } = await getAuthorizationCode(server, {
    clientId: reg.client_id,
    redirectUri: 'https://c.example.com/cb',
    scope: 'read',
  });
  assert.ok(code);
  const tok = body(
    await server.token(
      post({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: reg.client_id,
        client_secret: reg.client_secret,
        code_verifier: pkce.codeVerifier,
      }),
    ),
  );
  assert.ok(tok.access_token);
  assert.equal(tok.scope, 'read');
});

test('a code-grant registration without redirect_uris is invalid_redirect_uri', async () => {
  const { server } = buildRegistrationServer({ initialAccessToken: IAT });
  const res = await server.register(
    jsonPost({ grant_types: ['authorization_code'] }, { authorization: `Bearer ${IAT}` }),
  );
  assert.equal(body(res).error, 'invalid_redirect_uri');
});

test('open registration is allowed only when explicitly opened', async () => {
  const { server } = buildRegistrationServer({ open: true });
  const reg = body(await server.register(jsonPost({ redirect_uris: ['https://o/cb'] })));
  assert.ok(reg.client_id);
});
