import { test } from 'node:test';
import assert from 'node:assert/strict';

import { jwe, encrypt, decrypt, decode, decodeProtectedHeader, JweError, ErrorCode } from '../src/index.js';
import { SUPPORTED as SUPPORTED_ALG } from '../src/internal/algorithms.js';
import { SUPPORTED as SUPPORTED_ENC } from '../src/internal/encryptions.js';

// PACKAGE SURFACE

test('index exposes the public surface + frozen namespace', () => {
  assert.equal(typeof encrypt, 'function');
  assert.equal(typeof decrypt, 'function');
  assert.equal(typeof decode, 'function');
  assert.equal(typeof decodeProtectedHeader, 'function');
  assert.equal(typeof jwe.encrypt, 'function');
  assert.ok(Object.isFrozen(jwe));
});

// REGISTRIES

test('alg registry lists the curated set and excludes RSA1_5', () => {
  for (const alg of [
    'RSA-OAEP',
    'RSA-OAEP-256',
    'A128KW',
    'A256KW',
    'ECDH-ES',
    'ECDH-ES+A128KW',
    'ECDH-ES+A256KW',
    'dir',
  ]) {
    assert.ok(SUPPORTED_ALG.includes(alg), `${alg} should be supported`);
  }
  assert.ok(!SUPPORTED_ALG.includes('RSA1_5'), 'RSA1_5 must never be supported');
});

test('enc registry lists GCM + CBC-HMAC families', () => {
  for (const enc of ['A128GCM', 'A192GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512']) {
    assert.ok(SUPPORTED_ENC.includes(enc), `${enc} should be supported`);
  }
});

// DECODE (fully implemented in the scaffold)

test('decode splits a five-segment compact JWE without decrypting', () => {
  const header = Buffer.from(JSON.stringify({ alg: 'dir', enc: 'A256GCM', kid: 'k1' })).toString('base64url');
  const token = [header, '', 'aXYtYnl0ZXM', 'Y2lwaGVy', 'dGFn'].join('.');

  const decoded = decode(token);
  assert.deepEqual(decoded.header, { alg: 'dir', enc: 'A256GCM', kid: 'k1' });
  assert.equal(decoded.encryptedKey.length, 0, 'dir has an empty encrypted-key segment');
  assert.ok(Buffer.isBuffer(decoded.iv));
  assert.ok(Buffer.isBuffer(decoded.ciphertext));
  assert.ok(Buffer.isBuffer(decoded.tag));
});

test('decodeProtectedHeader returns only the header', () => {
  const header = Buffer.from(JSON.stringify({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })).toString('base64url');
  const token = [header, 'd3JhcHBlZA', 'aXY', 'Y3Q', 'dGFn'].join('.');
  assert.deepEqual(decodeProtectedHeader(token), { alg: 'RSA-OAEP-256', enc: 'A256GCM' });
});

test('decode rejects a token without exactly five segments', () => {
  assert.throws(
    () => decode('a.b.c'),
    err => err instanceof JweError && err.code === ErrorCode.INVALID_TOKEN,
  );
});

// STUBS (replaced by the encryption core; asserted so the marker can't rot silently)

test('encrypt / decrypt / encryptJson / decryptJson report NOT_IMPLEMENTED for now', async () => {
  for (const call of [
    () => encrypt({ a: 1 }, Buffer.alloc(32), { alg: 'dir', enc: 'A256GCM' }),
    () => decrypt('a.b.c.d.e', Buffer.alloc(32), { alg: ['dir'], enc: ['A256GCM'] }),
    () => jwe.encryptJson({ a: 1 }, [], {}),
    () => jwe.decryptJson({}, Buffer.alloc(32), { alg: ['dir'], enc: ['A256GCM'] }),
  ]) {
    await assert.rejects(call, err => err instanceof JweError && err.code === ErrorCode.NOT_IMPLEMENTED);
  }
});
