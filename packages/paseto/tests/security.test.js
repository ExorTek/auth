/**
 * Negative-path / abuse tests — the guarantees that make PASETO a safer
 * default than JWT.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  encrypt,
  decrypt,
  sign,
  verify,
  generateKey,
  generateKeyPair,
  keys,
  PasetoError,
  ErrorCode,
} from '../src/index.js';

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

test('malformed tokens (too few / too many segments) are rejected', () => {
  const key = generateKey();
  const valid = encrypt({ a: 1 }, key);
  for (const bad of ['v4.local', 'v4.local.', `${valid}.a.b`, 'not-a-token']) {
    assert.throws(
      () => decrypt(bad, key),
      err => err instanceof PasetoError && err.code === ErrorCode.INVALID_TOKEN,
    );
  }
});

test('an over-large token is rejected before any crypto (TOKEN_TOO_LARGE)', () => {
  const key = generateKey();
  const huge = `v4.local.${'A'.repeat(9000)}`;
  assert.throws(
    () => decrypt(huge, key),
    err => err instanceof PasetoError && err.code === ErrorCode.TOKEN_TOO_LARGE,
  );
  // A tighter maxTokenSize is honoured…
  const token = encrypt({ a: 1 }, key);
  assert.throws(
    () => decrypt(token, key, { maxTokenSize: 8 }),
    err => err.code === ErrorCode.TOKEN_TOO_LARGE,
  );
  // …and the default lets a normal token through.
  assert.equal(decrypt(token, key).a, 1);
});

test('a v4.local token is rejected by verify()', () => {
  const { publicKey } = generateKeyPair();
  const local = encrypt({ a: 1 }, generateKey());
  assert.throws(
    () => verify(local, publicKey),
    err => err instanceof PasetoError && err.code === ErrorCode.INVALID_TOKEN,
  );
});

// KEY PURPOSE (algorithm lucidity)

test('a public key can never be used as a v4.local key', () => {
  const { publicKey } = generateKeyPair();
  assert.throws(() => encrypt({ sub: 'forged' }, publicKey), { code: 'INVALID_KEY_PURPOSE' });
  // The raw bytes alone are refused too — they must be wrapped explicitly.
  assert.throws(() => encrypt({ sub: 'forged' }, publicKey.export()), { code: 'INVALID_KEY_PURPOSE' });
});

test('each operation only takes its own key purpose', () => {
  const local = generateKey();
  const { secretKey, publicKey } = generateKeyPair();
  assert.throws(() => sign({}, local), { code: 'INVALID_KEY_PURPOSE' });
  assert.throws(() => sign({}, publicKey), { code: 'INVALID_KEY_PURPOSE' });
  assert.throws(() => verify(sign({}, secretKey), secretKey), { code: 'INVALID_KEY_PURPOSE' });
  assert.throws(() => decrypt(encrypt({}, local), secretKey), { code: 'INVALID_KEY_PURPOSE' });
  assert.throws(() => encrypt({}, { version: 'v4', purpose: 'local' }), { code: 'INVALID_KEY_PURPOSE' });
});

test('keys.local / keys.public wrap existing raw material', () => {
  const raw = generateKey().export();
  const token = encrypt({ ok: 1 }, keys.local(raw));
  assert.equal(decrypt(token, keys.local(raw)).ok, 1);
  const { secretKey, publicKey } = generateKeyPair();
  assert.equal(verify(sign({ ok: 2 }, secretKey), keys.public(publicKey.export())).ok, 2);
});

test('a trailing "." (empty footer) is not a second spelling of the token', () => {
  const key = generateKey();
  const { secretKey, publicKey } = generateKeyPair();
  assert.throws(() => decrypt(`${encrypt({ a: 1 }, key)}.`, key), { code: 'INVALID_TOKEN' });
  assert.throws(() => verify(`${sign({ a: 1 }, secretKey)}.`, publicKey), { code: 'INVALID_TOKEN' });
});

test('claim requirements reject a payload that is not a claims object', () => {
  const { secretKey, publicKey } = generateKeyPair();
  const token = sign('user@x', secretKey);
  assert.throws(() => verify(token, publicKey, { issuer: 'https://as', audience: 'api' }), {
    code: 'CLAIM_MISMATCH',
  });
  assert.equal(verify(token, publicKey), 'user@x');
});
