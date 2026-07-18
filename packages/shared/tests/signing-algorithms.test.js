import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createSecretKey, randomBytes } from 'node:crypto';

import { lookup, SUPPORTED } from '../src/signing/algorithms.js';

test('SUPPORTED lists every RFC 7518 / 8037 / 8812 alg we ship', () => {
  const expected = [
    'HS256',
    'HS384',
    'HS512',
    'RS256',
    'RS384',
    'RS512',
    'PS256',
    'PS384',
    'PS512',
    'ES256',
    'ES384',
    'ES512',
    'ES256K',
    'EdDSA',
  ];
  assert.deepEqual([...SUPPORTED].sort(), expected.sort());
});

test('SUPPORTED does NOT contain `none`', () => {
  assert.equal(SUPPORTED.includes('none'), false);
  assert.equal(SUPPORTED.includes('None'), false);
});

test('lookup: unknown alg throws', () => {
  assert.throws(() => lookup('none'), /unsupported alg/);
  assert.throws(() => lookup('BOGUS'), /unsupported alg/);
});

test('HS256 sign / verify round-trip', async () => {
  const key = createSecretKey(randomBytes(32));
  const meta = lookup('HS256');
  const sig = await meta.sign(key, Buffer.from('m'));
  assert.equal(await meta.verify(key, Buffer.from('m'), sig), true);
});

test('HS256 detects tampering', async () => {
  const key = createSecretKey(randomBytes(32));
  const meta = lookup('HS256');
  const sig = await meta.sign(key, Buffer.from('m'));
  sig[0] ^= 0xff;
  assert.equal(await meta.verify(key, Buffer.from('m'), sig), false);
});

test('ES256 sign / verify round-trip', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const meta = lookup('ES256');
  const sig = await meta.sign(privateKey, Buffer.from('payload'));
  assert.equal(sig.length, 64);
  assert.equal(await meta.verify(publicKey, Buffer.from('payload'), sig), true);
});

test('RS256 sign / verify round-trip', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const meta = lookup('RS256');
  const sig = await meta.sign(privateKey, Buffer.from('m'));
  assert.equal(await meta.verify(publicKey, Buffer.from('m'), sig), true);
});

test('PS256 sign / verify round-trip', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const meta = lookup('PS256');
  const sig = await meta.sign(privateKey, Buffer.from('m'));
  assert.equal(await meta.verify(publicKey, Buffer.from('m'), sig), true);
});

test('EdDSA (Ed25519) sign / verify round-trip', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const meta = lookup('EdDSA');
  const sig = await meta.sign(privateKey, Buffer.from('m'));
  assert.equal(await meta.verify(publicKey, Buffer.from('m'), sig), true);
});
