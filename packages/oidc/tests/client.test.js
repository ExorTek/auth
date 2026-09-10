import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { ErrorCode, OidcError, createClient } from '../src/index.js';
import { makeSigner, startStubAS } from './helpers/oidc.js';

const CLIENT_ID = 'test-client';
const REDIRECT_URI = 'https://app.example.com/callback';

/** @type {Array<() => Promise<unknown>>} */
const cleanups = [];
afterEach(async () => {
  while (cleanups.length) {
    await cleanups.pop()();
  }
});

/**
 * Stand up a stub OP and an oidc client pointed at it. The token endpoint
 * serves whatever id_token the test mints into `holder.idToken` before the
 * exchange (the sync stub handler can't await, but the id_token is known
 * once `authorize` has produced the nonce).
 */
async function rig({ userinfo } = {}) {
  const signer = await makeSigner();
  const holder = { idToken: '' };
  const as = await startStubAS({
    publicJwks: [signer.publicJwk],
    token: () => ({
      access_token: 'access-token-value',
      token_type: 'Bearer',
      refresh_token: 'refresh-token-value',
      id_token: holder.idToken,
    }),
    userinfo,
  });
  cleanups.push(as.close);
  const client = createClient({
    issuer: as.issuer,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    // The stub AS serves its JWKS over http on loopback.
    jwksOptions: { allowInsecure: true },
  });
  return { as, client, signer, holder };
}

describe('createClient config guards', () => {
  it('rejects a non-object config', () => {
    assert.throws(() => createClient(null), { code: ErrorCode.INVALID_ARGUMENT });
  });

  it('rejects a missing issuer', () => {
    assert.throws(
      () => createClient({ clientId: 'a', redirectUri: REDIRECT_URI }),
      err => {
        assert.ok(err instanceof OidcError);
        assert.equal(err.code, ErrorCode.INVALID_ARGUMENT);
        assert.equal(err.status, 400);
        return true;
      },
    );
  });

  it('rejects a non-array scope', () => {
    assert.throws(
      () => createClient({ issuer: 'https://x', clientId: 'a', redirectUri: REDIRECT_URI, scope: 'openid' }),
      { code: ErrorCode.INVALID_ARGUMENT },
    );
  });
});

describe('createClient.authorize', () => {
  it('builds an authorization URL carrying openid scope, state and nonce', async () => {
    const { client } = await rig();
    const { url, session } = await client.authorize();
    const p = new URL(url).searchParams;
    assert.ok(p.get('scope').split(' ').includes('openid'));
    assert.ok(p.get('state'));
    assert.ok(p.get('nonce'));
    assert.ok(p.get('code_challenge'));
    assert.equal(typeof session, 'string');
  });

  it('threads OIDC auth params (prompt, login_hint, max_age) onto the URL', async () => {
    const { client } = await rig();
    const { url } = await client.authorize({ prompt: 'login', loginHint: 'a@b.com', maxAge: 3600 });
    const p = new URL(url).searchParams;
    assert.equal(p.get('prompt'), 'login');
    assert.equal(p.get('login_hint'), 'a@b.com');
    assert.equal(p.get('max_age'), '3600');
  });
});

describe('createClient.handleCallback', () => {
  it('verifies the id_token and returns claims + userinfo', async () => {
    const { as, client, signer, holder } = await rig({
      userinfo: () => ({ sub: 'user-123', email: 'user@example.com', name: 'Test User' }),
    });

    const { url, session } = await client.authorize();
    const params = new URL(url).searchParams;

    // Mint the id_token bound to this flow's nonce before the exchange.
    holder.idToken = await signer.mint({ iss: as.issuer, sub: 'user-123', aud: CLIENT_ID, nonce: params.get('nonce') });

    const result = await client.handleCallback({ code: 'auth-code', state: params.get('state') }, { session });

    assert.equal(result.claims.sub, 'user-123');
    assert.equal(result.claims.aud, CLIENT_ID);
    assert.equal(result.userinfo.email, 'user@example.com');
    assert.equal(typeof result.idToken, 'string');
    assert.equal(result.tokens.access_token, 'access-token-value');
  });

  it('rejects a callback whose id_token nonce does not match', async () => {
    const { as, client, signer, holder } = await rig();
    const { url, session } = await client.authorize();
    const params = new URL(url).searchParams;
    holder.idToken = await signer.mint({ iss: as.issuer, sub: 'user-123', aud: CLIENT_ID, nonce: 'wrong-nonce' });
    await assert.rejects(client.handleCallback({ code: 'auth-code', state: params.get('state') }, { session }));
  });
});
