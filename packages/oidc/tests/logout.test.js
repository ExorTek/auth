import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { ErrorCode, createClient, createProvider } from '../src/index.js';
import { _clearIssuerMetadataCache } from '../src/internal/issuer-discovery.js';
import { makeSigner, startStubAS } from './helpers/oidc.js';

const ISSUER = 'https://auth.example.com';
const CLIENT_ID = 'test-client';
const POST_LOGOUT = 'https://app.example.com/after-logout';

/** @type {Array<() => Promise<unknown>>} */
const cleanups = [];
afterEach(async () => {
  _clearIssuerMetadataCache();
  while (cleanups.length) {
    await cleanups.pop()();
  }
});

async function makeProvider() {
  const signer = await makeSigner();
  const provider = createProvider({
    issuer: ISSUER,
    signing: { key: signer.privateJwk, alg: signer.alg, kid: signer.kid },
    jwks: [signer.publicJwk],
    endpoints: { authorization: '/authorize', token: '/token' },
    logout: { postLogoutRedirectUris: [POST_LOGOUT] },
  });
  return { provider, signer };
}

describe('client.endSessionUrl', () => {
  it('discovers end_session_endpoint and builds the logout URL', async () => {
    const signer = await makeSigner();
    const as = await startStubAS({ publicJwks: [signer.publicJwk] });
    cleanups.push(as.close);

    const client = createClient({ issuer: as.issuer, clientId: CLIENT_ID, redirectUri: POST_LOGOUT });
    const hint = await signer.mint({ iss: as.issuer, sub: 'u1', aud: CLIENT_ID });
    const url = await client.endSessionUrl({ idTokenHint: hint, postLogoutRedirectUri: POST_LOGOUT, state: 'xyz' });

    const parsed = new URL(url);
    assert.equal(parsed.origin + parsed.pathname, `${as.base}/end_session`);
    assert.equal(parsed.searchParams.get('id_token_hint'), hint);
    assert.equal(parsed.searchParams.get('post_logout_redirect_uri'), POST_LOGOUT);
    assert.equal(parsed.searchParams.get('state'), 'xyz');
    assert.equal(parsed.searchParams.get('client_id'), CLIENT_ID);
  });

  it('prefers an explicit endSessionEndpoint over discovery', async () => {
    const client = createClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: POST_LOGOUT,
      endSessionEndpoint: 'https://auth.example.com/logout',
    });
    const url = await client.endSessionUrl({ idTokenHint: 'hint-token' });
    assert.equal(new URL(url).origin + new URL(url).pathname, 'https://auth.example.com/logout');
  });

  it('requires an idTokenHint', async () => {
    const client = createClient({ issuer: ISSUER, clientId: CLIENT_ID, redirectUri: POST_LOGOUT });
    await assert.rejects(client.endSessionUrl({}), { code: ErrorCode.INVALID_ARGUMENT });
  });
});

describe('provider.endSessionHandler', () => {
  it('advertises end_session_endpoint once logout is configured', async () => {
    const { provider } = await makeProvider();
    const doc = JSON.parse(provider.discoveryHandler()().body);
    assert.equal(doc.end_session_endpoint, `${ISSUER}/end_session`);
  });

  it('redirects to a registered post_logout_redirect_uri with state, and clears the session', async () => {
    const signer = await makeSigner();
    const seen = [];
    const provider = createProvider({
      issuer: ISSUER,
      signing: { key: signer.privateJwk, alg: signer.alg, kid: signer.kid },
      jwks: [signer.publicJwk],
      endpoints: { authorization: '/authorize', token: '/token' },
      logout: { postLogoutRedirectUris: [POST_LOGOUT], onLogout: ctx => seen.push(ctx.sub) },
    });
    const hint = await signer.mint({ iss: ISSUER, sub: 'user-9', aud: CLIENT_ID });

    const res = await provider.endSessionHandler()({
      query: { id_token_hint: hint, post_logout_redirect_uri: POST_LOGOUT, state: 's1' },
    });
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.location);
    assert.equal(loc.origin + loc.pathname, POST_LOGOUT);
    assert.equal(loc.searchParams.get('state'), 's1');
    assert.deepEqual(seen, ['user-9']);
  });

  it('rejects an unregistered post_logout_redirect_uri', async () => {
    const { provider } = await makeProvider();
    const res = await provider.endSessionHandler()({
      query: { post_logout_redirect_uri: 'https://evil.example/steal' },
    });
    assert.equal(res.status, 400);
  });

  it('returns a logged_out confirmation when no redirect is requested', async () => {
    const { provider } = await makeProvider();
    const res = await provider.endSessionHandler()({ query: {} });
    assert.equal(res.status, 200);
    assert.equal(JSON.parse(res.body).logged_out, true);
  });
});
