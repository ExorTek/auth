import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test, before, after } from 'node:test';

import { encode as base64urlEncode } from '@exortek/shared/base64url';

import { ErrorCode } from '../src/index.js';
import { createJwksResolver, verifyIdToken } from '../src/internal/id-token.js';
import { makeSigner, startStubAS } from './helpers/oidc.js';

let signer;
let as;
let jwks;

const CLIENT_ID = 'client-abc';

before(async () => {
  signer = await makeSigner();
  as = await startStubAS({ publicJwks: [signer.publicJwk] });
  jwks = createJwksResolver(as.jwksUri, { allowInsecure: true });
});

after(() => as.close());

const base = () => ({
  iss: as.issuer,
  sub: 'user-1',
  aud: CLIENT_ID,
  nonce: 'nonce-1',
});

test('verifies a well-formed id_token and returns its claims', async () => {
  const idToken = await signer.mint(base(), { expiresIn: '5m' });
  const { sub, claims } = await verifyIdToken(idToken, {
    jwks,
    issuer: as.issuer,
    clientId: CLIENT_ID,
    nonce: 'nonce-1',
  });
  assert.equal(sub, 'user-1');
  assert.equal(claims.aud, CLIENT_ID);
});

test('wrong audience → AUDIENCE_MISMATCH', async () => {
  const idToken = await signer.mint({ ...base(), aud: 'someone-else' }, { expiresIn: '5m' });
  await assert.rejects(verifyIdToken(idToken, { jwks, issuer: as.issuer, clientId: CLIENT_ID }), err => {
    assert.equal(err.code, ErrorCode.AUDIENCE_MISMATCH);
    return true;
  });
});

test('wrong issuer → ISSUER_MISMATCH', async () => {
  const idToken = await signer.mint({ ...base(), iss: 'https://evil.example' }, { expiresIn: '5m' });
  await assert.rejects(verifyIdToken(idToken, { jwks, issuer: as.issuer, clientId: CLIENT_ID }), err => {
    assert.equal(err.code, ErrorCode.ISSUER_MISMATCH);
    return true;
  });
});

test('nonce mismatch → NONCE_MISMATCH', async () => {
  const idToken = await signer.mint(base(), { expiresIn: '5m' });
  await assert.rejects(
    verifyIdToken(idToken, { jwks, issuer: as.issuer, clientId: CLIENT_ID, nonce: 'other-nonce' }),
    err => {
      assert.equal(err.code, ErrorCode.NONCE_MISMATCH);
      return true;
    },
  );
});

test('expired token → ID_TOKEN_INVALID', async () => {
  const idToken = await signer.mint({ ...base(), exp: Math.floor(Date.now() / 1000) - 60 });
  await assert.rejects(verifyIdToken(idToken, { jwks, issuer: as.issuer, clientId: CLIENT_ID }), err => {
    assert.equal(err.code, ErrorCode.ID_TOKEN_INVALID);
    return true;
  });
});

test('tampered signature → ID_TOKEN_INVALID', async () => {
  const idToken = await signer.mint(base(), { expiresIn: '5m' });
  const parts = idToken.split('.');
  const tampered = `${parts[0]}.${parts[1]}.${'A'.repeat(parts[2].length)}`;
  await assert.rejects(verifyIdToken(tampered, { jwks, issuer: as.issuer, clientId: CLIENT_ID }), err => {
    assert.equal(err.code, ErrorCode.ID_TOKEN_INVALID);
    return true;
  });
});

test('multi-audience token requires azp === clientId', async () => {
  const bad = await signer.mint({ ...base(), aud: [CLIENT_ID, 'other'], azp: 'other' }, { expiresIn: '5m' });
  await assert.rejects(verifyIdToken(bad, { jwks, issuer: as.issuer, clientId: CLIENT_ID }), err => {
    assert.equal(err.code, ErrorCode.AUDIENCE_MISMATCH);
    return true;
  });

  const good = await signer.mint({ ...base(), aud: [CLIENT_ID, 'other'], azp: CLIENT_ID }, { expiresIn: '5m' });
  const { sub } = await verifyIdToken(good, { jwks, issuer: as.issuer, clientId: CLIENT_ID });
  assert.equal(sub, 'user-1');
});

test('at_hash binds the access token when present', async () => {
  const accessToken = 'the-access-token';
  const digest = createHash('sha256').update(accessToken, 'ascii').digest();
  const at_hash = base64urlEncode(digest.subarray(0, digest.length / 2));

  const good = await signer.mint({ ...base(), at_hash }, { expiresIn: '5m' });
  const ok = await verifyIdToken(good, { jwks, issuer: as.issuer, clientId: CLIENT_ID, accessToken });
  assert.equal(ok.sub, 'user-1');

  await assert.rejects(
    verifyIdToken(good, { jwks, issuer: as.issuer, clientId: CLIENT_ID, accessToken: 'wrong-token' }),
    err => {
      assert.equal(err.code, ErrorCode.ID_TOKEN_INVALID);
      assert.match(err.message, /at_hash/);
      return true;
    },
  );
});
