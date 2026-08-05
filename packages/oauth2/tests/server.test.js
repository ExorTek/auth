import assert from 'node:assert/strict';
import { test } from 'node:test';

import { verify as jwtVerify } from '@exortek/jwt';

import { buildServer, getAuthorizationCode, dpopClient, post, get, body, ISSUER } from './helpers/server.js';

test('metadata advertises the AS capabilities (RFC 8414)', async () => {
  const { server } = buildServer();
  const res = server.metadata();
  assert.equal(res.status, 200);
  const doc = body(res);
  assert.equal(doc.issuer, ISSUER);
  assert.deepEqual(doc.response_types_supported, ['code']);
  assert.deepEqual(doc.code_challenge_methods_supported, ['S256']);
  assert.equal(doc.authorization_response_iss_parameter_supported, true);
  assert.ok(doc.token_endpoint.endsWith('/token'));
});

test('authorization code + PKCE round-trip issues access + refresh tokens', async () => {
  const { server, asKp } = buildServer();
  const { res, code, pkce, redirectUri } = await getAuthorizationCode(server, { scope: 'read write' });

  const loc = new URL(res.headers.location);
  assert.equal(loc.searchParams.get('state'), null); // none sent
  assert.equal(loc.searchParams.get('iss'), ISSUER); // RFC 9207 always present
  assert.ok(code);

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
  assert.equal(tok.token_type, 'Bearer');
  assert.equal(tok.scope, 'read write');
  assert.ok(tok.refresh_token);

  const { payload } = await jwtVerify(tok.access_token, asKp.publicKey, { alg: ['ES256'], issuer: ISSUER });
  assert.equal(payload.sub, 'user-1');
  assert.equal(payload.client_id, 'app');
});

test('a replayed authorization code is rejected', async () => {
  const { server } = buildServer();
  const { code, pkce, redirectUri } = await getAuthorizationCode(server);
  const tokenReq = () =>
    server.token(
      post({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: 'app',
        client_secret: 's3cret-value-strong',
        code_verifier: pkce.codeVerifier,
      }),
    );
  assert.equal((await tokenReq()).status, 200);
  const replay = body(await tokenReq());
  assert.equal(replay.error, 'invalid_grant');
});

test('a wrong PKCE verifier is invalid_grant', async () => {
  const { server } = buildServer();
  const { code, redirectUri } = await getAuthorizationCode(server);
  const res = await server.token(
    post({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: 'app',
      client_secret: 's3cret-value-strong',
      code_verifier: 'x'.repeat(50),
    }),
  );
  assert.equal(body(res).error, 'invalid_grant');
});

test('an unknown client is refused without a redirect', async () => {
  const { server } = buildServer();
  const res = await server.authorize(
    get('/authorize', {
      client_id: 'ghost',
      redirect_uri: 'https://app.example.com/cb',
      response_type: 'code',
      code_challenge: 'a'.repeat(43),
      code_challenge_method: 'S256',
    }),
  );
  // No trusted redirect_uri → direct JSON error, never a 302.
  assert.notEqual(res.status, 302);
  assert.equal(body(res).error, 'invalid_client');
});

test('an unregistered redirect_uri is refused without a redirect', async () => {
  const { server } = buildServer();
  const res = await server.authorize(
    get('/authorize', {
      client_id: 'app',
      redirect_uri: 'https://evil.example.com/cb',
      response_type: 'code',
      code_challenge: 'a'.repeat(43),
      code_challenge_method: 'S256',
    }),
  );
  assert.notEqual(res.status, 302);
  assert.equal(body(res).error, 'invalid_request');
});

test('missing PKCE challenge is rejected (secure by default)', async () => {
  const { server } = buildServer();
  const res = await server.authorize(
    get('/authorize', {
      client_id: 'app',
      redirect_uri: 'https://app.example.com/cb',
      response_type: 'code',
      state: 'st',
    }),
  );
  // Redirectable error — state echoed.
  const loc = new URL(res.headers.location);
  assert.equal(loc.searchParams.get('error'), 'invalid_request');
  assert.equal(loc.searchParams.get('state'), 'st');
});

test('refresh rotation + reuse detection burns the family', async () => {
  const { server } = buildServer();
  const { code, pkce, redirectUri } = await getAuthorizationCode(server, { scope: 'read' });
  const first = body(
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

  const rotated = body(
    await server.token(
      post({
        grant_type: 'refresh_token',
        refresh_token: first.refresh_token,
        client_id: 'app',
        client_secret: 's3cret-value-strong',
      }),
    ),
  );
  assert.ok(rotated.refresh_token);
  assert.notEqual(rotated.refresh_token, first.refresh_token);

  // Reusing the original (rotated-away) token trips reuse detection.
  const reuse = body(
    await server.token(
      post({
        grant_type: 'refresh_token',
        refresh_token: first.refresh_token,
        client_id: 'app',
        client_secret: 's3cret-value-strong',
      }),
    ),
  );
  assert.equal(reuse.error, 'invalid_grant');

  // The whole family is now dead — the rotated token no longer works.
  const dead = body(
    await server.token(
      post({
        grant_type: 'refresh_token',
        refresh_token: rotated.refresh_token,
        client_id: 'app',
        client_secret: 's3cret-value-strong',
      }),
    ),
  );
  assert.equal(dead.error, 'invalid_grant');
});

test('unsupported grant_type is rejected', async () => {
  const { server } = buildServer();
  const res = await server.token(post({ grant_type: 'password', username: 'x', password: 'y' }));
  assert.equal(body(res).error, 'unsupported_grant_type');
});

test('DPoP binds the access token to the client key (cnf.jkt)', async () => {
  const { server, asKp } = buildServer({
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

  // Without a proof the DPoP-required client is refused.
  const noProof = body(
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
  assert.equal(noProof.error, 'invalid_dpop_proof');

  const second = await getAuthorizationCode(server);
  const tok = body(
    await server.token(
      post(
        {
          grant_type: 'authorization_code',
          code: second.code,
          redirect_uri: second.redirectUri,
          client_id: 'app',
          client_secret: 's3cret-value-strong',
          code_verifier: second.pkce.codeVerifier,
        },
        { dpop: await dpop.proof('POST', `${ISSUER}/token`) },
      ),
    ),
  );
  assert.equal(tok.token_type, 'DPoP');
  const { payload } = await jwtVerify(tok.access_token, asKp.publicKey, { alg: ['ES256'], issuer: ISSUER });
  assert.equal(payload.cnf.jkt, dpop.jkt);
});

test('PAR pushes params and the request_uri is single-use', async () => {
  const { server } = buildServer({ security: { par: { required: true } } });

  // Front-channel authorize is refused when PAR is required.
  const direct = await server.authorize(
    get('/authorize', {
      client_id: 'app',
      redirect_uri: 'https://app.example.com/cb',
      response_type: 'code',
      code_challenge: 'a'.repeat(43),
      code_challenge_method: 'S256',
    }),
  );
  assert.equal(new URL(direct.headers.location).searchParams.get('error'), 'invalid_request');

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

  const ok = await server.authorize(get('/authorize', { request_uri: pushed.request_uri }));
  assert.ok(new URL(ok.headers.location).searchParams.get('code'));

  const reuse = await server.authorize(get('/authorize', { request_uri: pushed.request_uri }));
  assert.equal(body(reuse).error, 'invalid_request');
});

test('RAR authorization_details is validated and reflected into the token', async () => {
  const { server, asKp } = buildServer({ authorizationDetailsTypes: ['payment'] });
  const details = JSON.stringify([{ type: 'payment', amount: 42 }]);
  const { code, pkce, redirectUri } = await getAuthorizationCode(server, { extra: { authorization_details: details } });
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
  const { payload } = await jwtVerify(tok.access_token, asKp.publicKey, { alg: ['ES256'], issuer: ISSUER });
  assert.deepEqual(payload.authorization_details, [{ type: 'payment', amount: 42 }]);

  // An unsupported RAR type is refused at authorize.
  const bad = await server.authorize(
    get('/authorize', {
      client_id: 'app',
      redirect_uri: 'https://app.example.com/cb',
      response_type: 'code',
      state: 's',
      code_challenge: pkce.codeChallenge,
      code_challenge_method: 'S256',
      authorization_details: JSON.stringify([{ type: 'nope' }]),
    }),
  );
  assert.equal(new URL(bad.headers.location).searchParams.get('error'), 'invalid_authorization_details');
});

test('resource indicator restricts the token audience (RFC 8707)', async () => {
  const { server, asKp } = buildServer();
  const { code, pkce, redirectUri } = await getAuthorizationCode(server, {
    extra: { resource: 'https://api.example.com' },
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
  const { payload } = await jwtVerify(tok.access_token, asKp.publicKey, { alg: ['ES256'], issuer: ISSUER });
  assert.equal(payload.aud, 'https://api.example.com');
});

test('introspection and revocation of a refresh token', async () => {
  const { server } = buildServer();
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

  const active = body(
    await server.introspect(post({ token: tok.refresh_token, client_id: 'app', client_secret: 's3cret-value-strong' })),
  );
  assert.equal(active.active, true);
  assert.equal(active.token_type, 'refresh_token');

  const revoked = await server.revoke(
    post({ token: tok.refresh_token, client_id: 'app', client_secret: 's3cret-value-strong' }),
  );
  assert.equal(revoked.status, 200);

  const afterRevoke = body(
    await server.introspect(post({ token: tok.refresh_token, client_id: 'app', client_secret: 's3cret-value-strong' })),
  );
  assert.equal(afterRevoke.active, false);
});
