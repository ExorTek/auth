import assert from 'node:assert/strict';
import { test, before, after } from 'node:test';

import { ErrorCode } from '../src/index.js';
import { defineProvider, buildAuthorization, handleCallback, WarningCode } from '../src/providers/_base.js';
import { makeSigner, startStubAS } from './helpers/oidc.js';

const CLIENT_ID = 'client-abc';
const REDIRECT = 'https://app.com/auth/test/callback';

let signer;
let as;
let idTokenToServe; // set per-flow so the id_token echoes the live nonce
let grantedScope;

before(async () => {
  signer = await makeSigner();
  as = await startStubAS({
    publicJwks: [signer.publicJwk],
    token: () => ({
      access_token: 'access-1',
      token_type: 'Bearer',
      id_token: idTokenToServe,
      scope: grantedScope,
    }),
    userinfo: () => ({ sub: 'user-1', email: 'a@b.com', email_verified: true, name: 'A B', picture: 'p' }),
  });
});

after(() => as.close());

function oidcProvider(overrides = {}) {
  return defineProvider({
    id: 'test',
    kind: 'oidc',
    authorizationEndpoint: `${as.base}/authorize`,
    tokenEndpoint: `${as.base}/token`,
    userinfoEndpoint: `${as.base}/userinfo`,
    jwksUri: as.jwksUri,
    issuer: as.issuer,
    defaultScopes: ['email', 'profile'],
    jwksOptions: { allowInsecure: true },
    mapUser: raw => ({
      sub: raw.sub,
      email: raw.email,
      emailVerified: raw.email_verified,
      name: raw.name,
      picture: raw.picture,
    }),
    ...overrides,
  })({ clientId: CLIENT_ID, clientSecret: 'secret' });
}

/** Drive authorize → mint a matching id_token → return {session}. */
async function startFlow(provider, buildOpts = {}) {
  const { url, session, warnings } = await buildAuthorization(provider, { redirectUri: REDIRECT, ...buildOpts });
  idTokenToServe = await signer.mint(
    { iss: as.issuer, sub: 'user-1', aud: CLIENT_ID, nonce: session.nonce },
    { expiresIn: '5m' },
  );
  return { url, session, warnings };
}

test('buildAuthorization emits PKCE, state, nonce and openid scope for OIDC', async () => {
  const provider = oidcProvider();
  const { url, session } = await buildAuthorization(provider, { redirectUri: REDIRECT });
  const params = new URL(url).searchParams;

  assert.equal(params.get('response_type'), 'code');
  assert.equal(params.get('client_id'), CLIENT_ID);
  assert.equal(params.get('redirect_uri'), REDIRECT);
  assert.equal(params.get('code_challenge_method'), 'S256');
  assert.ok(params.get('code_challenge'));
  assert.equal(params.get('state'), session.state);
  assert.equal(params.get('nonce'), session.nonce);
  assert.deepEqual(params.get('scope').split(' '), ['openid', 'email', 'profile']);
  assert.ok(session.codeVerifier);
});

test('happy path resolves a normalized user', async () => {
  const provider = oidcProvider();
  grantedScope = 'openid email profile';
  const { session } = await startFlow(provider);
  const { user, warnings } = await handleCallback(provider, {
    redirectUri: REDIRECT,
    query: { code: 'code-1', state: session.state },
    session,
  });
  assert.equal(user.sub, 'user-1');
  assert.equal(user.email, 'a@b.com');
  assert.equal(user.provider, 'test');
  assert.equal(user.emailVerified, true);
  assert.deepEqual(warnings, []);
});

test('state mismatch throws STATE_MISMATCH', async () => {
  const provider = oidcProvider();
  const { session } = await startFlow(provider);
  await assert.rejects(
    handleCallback(provider, { redirectUri: REDIRECT, query: { code: 'c', state: 'forged' }, session }),
    err => {
      assert.equal(err.code, ErrorCode.STATE_MISMATCH);
      return true;
    },
  );
});

test('provider error is surfaced, not crashed', async () => {
  const provider = oidcProvider();
  const { session } = await startFlow(provider);
  await assert.rejects(
    handleCallback(provider, {
      redirectUri: REDIRECT,
      query: { error: 'access_denied', error_description: 'nope', state: session.state },
      session,
    }),
    err => {
      assert.equal(err.code, ErrorCode.PROVIDER_ERROR);
      assert.match(err.message, /access_denied/);
      return true;
    },
  );
});

test('cross-provider session is rejected (COAT)', async () => {
  const provider = oidcProvider();
  const { session } = await startFlow(provider);
  const other = oidcProvider({ id: 'other' });
  await assert.rejects(
    handleCallback(other, { redirectUri: REDIRECT, query: { code: 'c', state: session.state }, session }),
    err => {
      assert.equal(err.code, ErrorCode.CONTEXT_MISMATCH);
      return true;
    },
  );
});

test('iss response param mismatch throws ISSUER_MISMATCH', async () => {
  const provider = oidcProvider();
  const { session } = await startFlow(provider);
  await assert.rejects(
    handleCallback(provider, {
      redirectUri: REDIRECT,
      query: { code: 'c', state: session.state, iss: 'https://evil.example' },
      session,
    }),
    err => {
      assert.equal(err.code, ErrorCode.ISSUER_MISMATCH);
      return true;
    },
  );
});

test('a provider that advertises iss rejects a callback that omits it (RFC 9207)', async () => {
  // requireIssParam marks a provider known to return `iss` — an attacker can
  // no longer strip it to skip the mix-up check.
  const provider = oidcProvider({ requireIssParam: true });
  const { session } = await startFlow(provider);
  await assert.rejects(
    handleCallback(provider, {
      redirectUri: REDIRECT,
      query: { code: 'c', state: session.state }, // no iss
      session,
    }),
    err => {
      assert.equal(err.code, ErrorCode.ISSUER_MISMATCH);
      return true;
    },
  );
});

test('a provider that does not advertise iss still accepts an absent iss', async () => {
  const provider = oidcProvider(); // no requireIssParam
  grantedScope = 'openid email profile';
  const { session } = await startFlow(provider);
  const { user } = await handleCallback(provider, {
    redirectUri: REDIRECT,
    query: { code: 'code-1', state: session.state }, // no iss — allowed
    session,
  });
  assert.equal(user.sub, 'user-1');
});

test('userinfo sub that disagrees with the id_token throws SUB_MISMATCH', async () => {
  const provider = oidcProvider({
    userinfoEndpoint: `${as.base}/userinfo`,
    mapUser: raw => ({ sub: raw.sub }),
  });
  // Mint an id_token for a different subject than userinfo returns.
  const { url, session } = await buildAuthorization(provider, { redirectUri: REDIRECT });
  void url;
  idTokenToServe = await signer.mint(
    { iss: as.issuer, sub: 'someone-else', aud: CLIENT_ID, nonce: session.nonce },
    { expiresIn: '5m' },
  );
  await assert.rejects(
    handleCallback(provider, { redirectUri: REDIRECT, query: { code: 'c', state: session.state }, session }),
    err => {
      assert.equal(err.code, ErrorCode.SUB_MISMATCH);
      return true;
    },
  );
});

test('scope narrowing surfaces a warning', async () => {
  const provider = oidcProvider();
  grantedScope = 'openid email'; // profile dropped
  const { session } = await startFlow(provider);
  const { warnings } = await handleCallback(provider, {
    redirectUri: REDIRECT,
    query: { code: 'c', state: session.state },
    session,
  });
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0].code, WarningCode.SCOPE_NARROWED);
  assert.match(warnings[0].message, /profile/);
});

test('session binding mismatch throws SESSION_MISMATCH', async () => {
  const provider = oidcProvider();
  grantedScope = 'openid email profile';
  const { session } = await startFlow(provider, { sessionBinding: 'user-session-1' });
  await assert.rejects(
    handleCallback(provider, {
      redirectUri: REDIRECT,
      query: { code: 'c', state: session.state },
      session,
      sessionBinding: 'a-different-session',
    }),
    err => {
      assert.equal(err.code, ErrorCode.SESSION_MISMATCH);
      return true;
    },
  );
});
