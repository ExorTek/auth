/**
 * Negative-path / abuse tests — the guarantees that make PASETO a safer
 * default than JWT.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { encrypt, decrypt, sign, verify, generateKey, generateKeyPair, PasetoError, ErrorCode } from '../src/index.js';

test('expired token is rejected with TOKEN_EXPIRED', () => {
  const key = generateKey();
  const token = encrypt({ a: 1 }, key, { expiresIn: '-1s' });
  assert.throws(
    () => decrypt(token, key),
    err => err instanceof PasetoError && err.code === ErrorCode.TOKEN_EXPIRED,
  );
});

test('clockTolerance lets a just-expired token through', () => {
  const key = generateKey();
  const token = encrypt({ a: 1 }, key, { expiresIn: '-2s' });
  assert.equal(decrypt(token, key, { clockTolerance: '10s' }).a, 1);
});

test('not-yet-valid token is rejected with NOT_YET_VALID', () => {
  const key = generateKey();
  const token = encrypt({ a: 1 }, key, { notBefore: '1h' });
  assert.throws(
    () => decrypt(token, key),
    err => err instanceof PasetoError && err.code === ErrorCode.NOT_YET_VALID,
  );
});

test('issuer / subject / audience mismatches raise CLAIM_MISMATCH', () => {
  const key = generateKey();
  const token = encrypt({ x: 1 }, key, { issuer: 'a', subject: 's', audience: 'aud1' });
  assert.equal(decrypt(token, key, { issuer: 'a', subject: 's', audience: 'aud1' }).x, 1);
  for (const bad of [{ issuer: 'b' }, { subject: 't' }, { audience: 'aud2' }]) {
    assert.throws(
      () => decrypt(token, key, bad),
      err => err.code === ErrorCode.CLAIM_MISMATCH,
    );
  }
});

test('a v4.local token cannot be decrypted with the wrong key', () => {
  const token = encrypt({ a: 1 }, generateKey());
  assert.throws(
    () => decrypt(token, generateKey()),
    err => err.code === ErrorCode.DECRYPTION_FAILED,
  );
});

test('a tampered v4.public body fails verification', () => {
  const { secretKey, publicKey } = generateKeyPair();
  const token = sign({ a: 1 }, secretKey);
  const i = 15;
  const tampered = token.slice(0, i) + (token[i] === 'A' ? 'B' : 'A') + token.slice(i + 1);
  assert.throws(
    () => verify(tampered, publicKey),
    err => err instanceof PasetoError && err.code === ErrorCode.SIGNATURE_INVALID,
  );
});

test('purpose confusion: a v4.public token is not a v4.local token', () => {
  const key = generateKey();
  const { secretKey } = generateKeyPair();
  const pub = sign({ a: 1 }, secretKey);
  assert.throws(
    () => decrypt(pub, key),
    err => err instanceof PasetoError && err.code === ErrorCode.INVALID_TOKEN,
  );
});

test('a v4.local token is rejected by verify()', () => {
  const { publicKey } = generateKeyPair();
  const local = encrypt({ a: 1 }, generateKey());
  assert.throws(
    () => verify(local, publicKey),
    err => err instanceof PasetoError && err.code === ErrorCode.INVALID_TOKEN,
  );
});
