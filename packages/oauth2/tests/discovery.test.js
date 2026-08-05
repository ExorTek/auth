import assert from 'node:assert/strict';
import { test, afterEach } from 'node:test';

import { ErrorCode } from '../src/index.js';
import { discover, _clearDiscoveryCache } from '../src/internal/discovery.js';
import { makeSigner, startStubAS } from './helpers/oidc.js';

afterEach(() => _clearDiscoveryCache());

test('pulls endpoints from /.well-known/openid-configuration', async () => {
  const signer = await makeSigner();
  const as = await startStubAS({ publicJwks: [signer.publicJwk] });
  try {
    const doc = await discover(as.issuer);
    assert.equal(doc.issuer, as.issuer);
    assert.equal(doc.authorizationEndpoint, `${as.base}/authorize`);
    assert.equal(doc.tokenEndpoint, `${as.base}/token`);
    assert.equal(doc.userinfoEndpoint, `${as.base}/userinfo`);
    assert.equal(doc.jwksUri, `${as.base}/.well-known/jwks.json`);
  } finally {
    await as.close();
  }
});

test('rejects an issuer that does not match the document', async () => {
  const signer = await makeSigner();
  // Serve a discovery doc whose `issuer` is a lie.
  const as = await startStubAS({ publicJwks: [signer.publicJwk], extraDiscovery: { issuer: 'https://evil.example' } });
  try {
    await assert.rejects(discover(as.issuer), err => {
      assert.equal(err.code, ErrorCode.DISCOVERY_FAILED);
      assert.match(err.message, /does not match/);
      return true;
    });
  } finally {
    await as.close();
  }
});
