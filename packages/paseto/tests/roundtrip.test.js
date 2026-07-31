/**
 * High-level round-trips + claim behaviour for both purposes.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { encrypt, decrypt, sign, verify, generateKey, generateKeyPair, PasetoError, ErrorCode } from '../src/index.js';

// v4.local

test('v4.local round-trips an object payload', () => {
  const key = generateKey();
  const token = encrypt({ userId: 1, role: 'admin' }, key);
  assert.ok(token.startsWith('v4.local.'));
  const data = decrypt(token, key);
  assert.equal(data.userId, 1);
  assert.equal(data.role, 'admin');
});

test('v4.local stamps iat and honours expiresIn → exp', () => {
  const key = generateKey();
  const data = decrypt(encrypt({ a: 1 }, key, { expiresIn: '1h' }), key);
  assert.ok(typeof data.iat === 'string');
  assert.ok(typeof data.exp === 'string');
  assert.ok(Date.parse(data.exp) > Date.parse(data.iat));
});

test('v4.local string payloads pass through without claim injection', () => {
  const key = generateKey();
  const data = decrypt(encrypt('just a string', key), key);
  assert.equal(data, 'just a string');
});

test('v4.local footer is authenticated and returned with complete:true', () => {
  const key = generateKey();
  const token = encrypt({ a: 1 }, key, { footer: { kid: 'k1' } });
  const res = decrypt(token, key, { complete: true });
  assert.equal(res.footer, '{"kid":"k1"}');
  assert.equal(res.version, 'v4');
  assert.equal(res.purpose, 'local');
});

// v4.public

test('v4.public round-trips and verifies', () => {
  const { secretKey, publicKey } = generateKeyPair();
  const token = sign({ userId: 2 }, secretKey, { expiresIn: '1h' });
  assert.ok(token.startsWith('v4.public.'));
  const payload = verify(token, publicKey);
  assert.equal(payload.userId, 2);
});

test('v4.public accepts a 32-byte seed as the secret key', () => {
  const { secretKey, publicKey } = generateKeyPair();
  const seedOnly = secretKey.subarray(0, 32);
  const token = sign({ ok: true }, seedOnly);
  assert.equal(verify(token, publicKey).ok, true);
});

// implicit assertions

test('implicit assertion must match on the way back', () => {
  const key = generateKey();
  const token = encrypt({ a: 1 }, key, { assertion: 'tenant-42' });
  assert.equal(decrypt(token, key, { assertion: 'tenant-42' }).a, 1);
  assert.throws(
    () => decrypt(token, key, { assertion: 'tenant-99' }),
    err => err instanceof PasetoError && err.code === ErrorCode.DECRYPTION_FAILED,
  );
});
