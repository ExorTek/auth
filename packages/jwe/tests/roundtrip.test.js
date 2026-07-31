import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, generateKeyPairSync } from 'node:crypto';

import { encrypt, decrypt } from '../src/index.js';

const ENC_CEK_BYTES = {
  A128GCM: 16,
  A192GCM: 24,
  A256GCM: 32,
  'A128CBC-HS256': 32,
  'A256CBC-HS512': 64,
};

const ALL_ENC = Object.keys(ENC_CEK_BYTES);

const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const ecP256 = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const ecP384 = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
const x25519 = generateKeyPairSync('x25519');

const PAYLOAD = { sub: 'user-42', roles: ['admin', 'billing'], n: 7 };

/**
 * Encrypt then decrypt, asserting the payload survives and the header
 * advertises the expected alg/enc.
 */
async function roundtrip(t, { alg, enc, encKey, decKey }) {
  const token = await encrypt(PAYLOAD, encKey, { alg, enc });
  assert.equal(token.split('.').length, 5, `${alg}+${enc}: compact JWE has five segments`);
  const { payload, protectedHeader } = await decrypt(token, decKey, { alg: [alg], enc: [enc] });
  assert.deepEqual(payload, PAYLOAD, `${alg}+${enc}: payload round-trips`);
  assert.equal(protectedHeader.alg, alg);
  assert.equal(protectedHeader.enc, enc);
}

// dir — over every content-encryption algorithm

for (const enc of ALL_ENC) {
  test(`dir + ${enc}`, async t => {
    const key = randomBytes(ENC_CEK_BYTES[enc]);
    await roundtrip(t, { alg: 'dir', enc, encKey: key, decKey: key });
  });
}

// AES-KW

test('A128KW + A256GCM', async t => {
  const kek = randomBytes(16);
  await roundtrip(t, { alg: 'A128KW', enc: 'A256GCM', encKey: kek, decKey: kek });
});

test('A256KW + A128CBC-HS256', async t => {
  const kek = randomBytes(32);
  await roundtrip(t, { alg: 'A256KW', enc: 'A128CBC-HS256', encKey: kek, decKey: kek });
});

// RSA-OAEP

test('RSA-OAEP + A256GCM', async t => {
  await roundtrip(t, { alg: 'RSA-OAEP', enc: 'A256GCM', encKey: rsa.publicKey, decKey: rsa.privateKey });
});

test('RSA-OAEP-256 + A256CBC-HS512', async t => {
  await roundtrip(t, { alg: 'RSA-OAEP-256', enc: 'A256CBC-HS512', encKey: rsa.publicKey, decKey: rsa.privateKey });
});

// ECDH-ES direct

test('ECDH-ES + A256GCM (P-256)', async t => {
  await roundtrip(t, { alg: 'ECDH-ES', enc: 'A256GCM', encKey: ecP256.publicKey, decKey: ecP256.privateKey });
});

test('ECDH-ES + A256GCM (X25519)', async t => {
  await roundtrip(t, { alg: 'ECDH-ES', enc: 'A256GCM', encKey: x25519.publicKey, decKey: x25519.privateKey });
});

test('ECDH-ES + A256CBC-HS512 (P-384) — two-block Concat KDF', async t => {
  await roundtrip(t, { alg: 'ECDH-ES', enc: 'A256CBC-HS512', encKey: ecP384.publicKey, decKey: ecP384.privateKey });
});

// ECDH-ES + key wrap

test('ECDH-ES+A128KW + A256GCM (P-256)', async t => {
  await roundtrip(t, { alg: 'ECDH-ES+A128KW', enc: 'A256GCM', encKey: ecP256.publicKey, decKey: ecP256.privateKey });
});

test('ECDH-ES+A256KW + A256GCM (X25519)', async t => {
  await roundtrip(t, { alg: 'ECDH-ES+A256KW', enc: 'A256GCM', encKey: x25519.publicKey, decKey: x25519.privateKey });
});

// Payload shapes

test('string payload round-trips as raw bytes → string', async () => {
  const key = randomBytes(32);
  const token = await encrypt('hello world', key, { alg: 'dir', enc: 'A256GCM' });
  const { payload } = await decrypt(token, key, { alg: ['dir'], enc: ['A256GCM'] });
  assert.equal(Buffer.isBuffer(payload) ? payload.toString('utf8') : payload, 'hello world');
});

test('binary payload round-trips untouched', async () => {
  const key = randomBytes(32);
  const bytes = randomBytes(64);
  const token = await encrypt(bytes, key, { alg: 'dir', enc: 'A256GCM' });
  const { payload } = await decrypt(token, key, { alg: ['dir'], enc: ['A256GCM'] });
  assert.ok(Buffer.isBuffer(payload) && payload.equals(bytes));
});

test('accepts JWK key input', async () => {
  const jwk = rsa.publicKey.export({ format: 'jwk' });
  const privJwk = rsa.privateKey.export({ format: 'jwk' });
  const token = await encrypt(PAYLOAD, jwk, { alg: 'RSA-OAEP-256', enc: 'A256GCM' });
  const { payload } = await decrypt(token, privJwk, { alg: ['RSA-OAEP-256'], enc: ['A256GCM'] });
  assert.deepEqual(payload, PAYLOAD);
});

test('kid and extra header params land in the protected header', async () => {
  const key = randomBytes(32);
  const token = await encrypt(PAYLOAD, key, { alg: 'dir', enc: 'A256GCM', kid: 'k-9', header: { cty: 'JWT' } });
  const { protectedHeader } = await decrypt(token, key, { alg: ['dir'], enc: ['A256GCM'] });
  assert.equal(protectedHeader.kid, 'k-9');
  assert.equal(protectedHeader.cty, 'JWT');
});

test('apu / apv bind into the ECDH-ES derivation and travel in the header', async () => {
  const token = await encrypt(PAYLOAD, ecP256.publicKey, {
    alg: 'ECDH-ES+A256KW',
    enc: 'A256GCM',
    apu: 'Alice',
    apv: 'Bob',
  });
  const { protectedHeader, payload } = await decrypt(token, ecP256.privateKey, {
    alg: ['ECDH-ES+A256KW'],
    enc: ['A256GCM'],
  });
  assert.equal(Buffer.from(protectedHeader.apu, 'base64url').toString('utf8'), 'Alice');
  assert.deepEqual(payload, PAYLOAD);
});
