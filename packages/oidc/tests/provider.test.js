import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { ErrorCode, createProvider } from '../src/index.js';
import { makeSigner } from './helpers/oidc.js';

const ISSUER = 'https://auth.example.com';

async function makeProvider(overrides = {}) {
  const signer = await makeSigner();
  const provider = createProvider({
    issuer: ISSUER,
    signing: { key: signer.privateJwk, alg: signer.alg, kid: signer.kid },
    jwks: [signer.publicJwk],
    endpoints: { authorization: '/authorize', token: '/token' },
    claims: { supported: ['sub', 'email', 'email_verified', 'name'] },
    userinfo: { resolve: () => null },
    ...overrides,
  });
  return { provider, signer };
}

describe('createProvider config guards', () => {
  it('rejects a non-object config', () => {
    assert.throws(() => createProvider(null), { code: ErrorCode.INVALID_ARGUMENT });
  });

  it('rejects missing signing', () => {
    assert.throws(() => createProvider({ issuer: ISSUER, endpoints: { authorization: '/a', token: '/t' } }), {
      code: ErrorCode.INVALID_ARGUMENT,
    });
  });

  it('rejects endpoints without authorization/token', async () => {
    const signer = await makeSigner();
    assert.throws(
      () => createProvider({ issuer: ISSUER, signing: { key: signer.privateJwk, alg: signer.alg }, endpoints: {} }),
      { code: ErrorCode.INVALID_ARGUMENT },
    );
  });
});

describe('discoveryHandler', () => {
  it('serves an OIDC discovery document with resolved absolute endpoints', async () => {
    const { provider } = await makeProvider();
    const res = provider.discoveryHandler()();
    assert.equal(res.status, 200);
    assert.match(res.headers['cache-control'], /max-age/);
    const doc = JSON.parse(res.body);
    assert.equal(doc.issuer, ISSUER);
    assert.equal(doc.authorization_endpoint, `${ISSUER}/authorize`);
    assert.equal(doc.token_endpoint, `${ISSUER}/token`);
    assert.equal(doc.userinfo_endpoint, `${ISSUER}/userinfo`);
    assert.equal(doc.jwks_uri, `${ISSUER}/.well-known/jwks.json`);
    assert.deepEqual(doc.response_types_supported, ['code']);
    assert.deepEqual(doc.subject_types_supported, ['public']);
    assert.deepEqual(doc.code_challenge_methods_supported, ['S256']);
    assert.ok(doc.id_token_signing_alg_values_supported.includes('ES256'));
    assert.ok(doc.claims_supported.includes('email'));
  });

  it('omits end_session/check_session until they are configured', async () => {
    const { provider } = await makeProvider();
    const doc = JSON.parse(provider.discoveryHandler()().body);
    assert.equal('end_session_endpoint' in doc, false);
    assert.equal('check_session_iframe' in doc, false);
  });
});

describe('jwksHandler', () => {
  it('publishes the configured public JWK set', async () => {
    const { provider, signer } = await makeProvider();
    const res = provider.jwksHandler()();
    assert.equal(res.status, 200);
    const body = JSON.parse(res.body);
    assert.equal(body.keys.length, 1);
    assert.equal(body.keys[0].kid, signer.kid);
    assert.equal(body.keys[0].kty, 'EC');
  });
});

describe('idTokenSigner', () => {
  it('signs a verifiable id_token', async () => {
    const { provider } = await makeProvider();
    const idToken = await provider.idTokenSigner.sign({
      subject: 'user-1',
      clientId: 'client-1',
      issuer: ISSUER,
      nonce: 'n-1',
    });
    assert.equal(typeof idToken, 'string');
    assert.equal(idToken.split('.').length, 3);
  });
});

describe('userinfoHandler', () => {
  const resolve = async token => {
    if (token !== 'good-token') {
      return null;
    }
    return {
      sub: 'user-1',
      scope: 'openid email profile',
      claims: { email: 'u@example.com', email_verified: true, name: 'U', phone_number: '+100' },
    };
  };

  it('returns sub + scope-releasable claims, filtered by the userinfo policy', async () => {
    const { provider } = await makeProvider({
      userinfo: { resolve },
      claims: { supported: ['sub', 'email', 'name'], userinfo: ['email', 'email_verified', 'name'] },
    });
    const res = await provider.userinfoHandler()({ headers: { authorization: 'Bearer good-token' } });
    assert.equal(res.status, 200);
    assert.equal(res.headers['cache-control'], 'no-store');
    const body = JSON.parse(res.body);
    assert.equal(body.sub, 'user-1');
    assert.equal(body.email, 'u@example.com');
    assert.equal(body.email_verified, true);
    assert.equal(body.name, 'U');
    // phone_number is not released — `phone` scope was not granted.
    assert.equal('phone_number' in body, false);
  });

  it('401s with WWW-Authenticate when no token is present', async () => {
    const { provider } = await makeProvider({ userinfo: { resolve } });
    const res = await provider.userinfoHandler()({ headers: {} });
    assert.equal(res.status, 401);
    assert.match(res.headers['www-authenticate'], /Bearer/);
  });

  it('401s invalid_token when the token does not resolve', async () => {
    const { provider } = await makeProvider({ userinfo: { resolve } });
    const res = await provider.userinfoHandler()({ headers: { authorization: 'Bearer nope' } });
    assert.equal(res.status, 401);
    assert.match(res.headers['www-authenticate'], /invalid_token/);
  });

  it('throws INVALID_ARGUMENT if userinfo.resolve is missing', async () => {
    const { provider } = await makeProvider({ userinfo: undefined });
    assert.throws(() => provider.userinfoHandler(), { code: ErrorCode.INVALID_ARGUMENT });
  });
});
