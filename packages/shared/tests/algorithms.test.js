import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createSecretKey, randomBytes } from 'node:crypto';

import { hmac, rsaPkcs1, rsaPss, ecdsa, eddsa, createRegistry } from '../src/algorithms.js';

function jwtLikeRegistry() {
  return createRegistry({
    HS256: hmac('HS256', 'sha256'),
    HS384: hmac('HS384', 'sha384'),
    HS512: hmac('HS512', 'sha512'),
    RS256: rsaPkcs1('RS256', 'sha256'),
    PS256: rsaPss('PS256', 'sha256'),
    ES256: ecdsa('ES256', 'sha256', 'P-256'),
    ES256K: ecdsa('ES256K', 'sha256', 'secp256k1'),
    EdDSA: eddsa(),
  });
}

test('createRegistry: SUPPORTED reflects the exact keys the caller passed', () => {
  const r = jwtLikeRegistry();
  const got = new Set(r.SUPPORTED);
  for (const alg of ['HS256', 'HS384', 'HS512', 'RS256', 'PS256', 'ES256', 'ES256K', 'EdDSA']) {
    assert.ok(got.has(alg), `expected ${alg} to be supported`);
  }
  assert.equal(r.SUPPORTED.length, 8);
});

test('createRegistry: two callers can ship different subsets', () => {
  const jwsLike = createRegistry({ HS256: hmac('HS256', 'sha256'), EdDSA: eddsa() });
  const jwtLike = createRegistry({ ES256: ecdsa('ES256', 'sha256', 'P-256'), EdDSA: eddsa() });
  assert.deepEqual(new Set(jwsLike.SUPPORTED), new Set(['HS256', 'EdDSA']));
  assert.deepEqual(new Set(jwtLike.SUPPORTED), new Set(['ES256', 'EdDSA']));
  // A caller can drop ES256 or add a new alg without touching shared.
  assert.equal(jwsLike.SUPPORTED.includes('ES256'), false);
});

test('lookup: unknown alg throws — supported list included in message', () => {
  const r = jwtLikeRegistry();
  try {
    r.lookup('BOGUS');
    assert.fail('should throw');
  } catch (err) {
    assert.match(err.message, /unsupported alg "BOGUS"/);
    assert.match(err.message, /HS256/);
  }
});

test("lookup: alg 'none' is not in the registry and throws", () => {
  const r = jwtLikeRegistry();
  assert.throws(() => r.lookup('none'), /unsupported alg/);
});

test('HS256 round-trip via factory', async () => {
  const key = createSecretKey(randomBytes(32));
  const meta = hmac('HS256', 'sha256');
  const sig = await meta.sign(key, Buffer.from('m'));
  assert.equal(await meta.verify(key, Buffer.from('m'), sig), true);
});

test('HS256 tamper detection', async () => {
  const key = createSecretKey(randomBytes(32));
  const meta = hmac('HS256', 'sha256');
  const sig = await meta.sign(key, Buffer.from('m'));
  sig[0] ^= 0xff;
  assert.equal(await meta.verify(key, Buffer.from('m'), sig), false);
});

test('ES256 round-trip via factory', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const meta = ecdsa('ES256', 'sha256', 'P-256');
  const sig = await meta.sign(privateKey, Buffer.from('m'));
  assert.equal(sig.length, 64);
  assert.equal(await meta.verify(publicKey, Buffer.from('m'), sig), true);
});

test('RS256 round-trip via factory', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const meta = rsaPkcs1('RS256', 'sha256');
  const sig = await meta.sign(privateKey, Buffer.from('m'));
  assert.equal(await meta.verify(publicKey, Buffer.from('m'), sig), true);
});

test('PS256 round-trip via factory', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const meta = rsaPss('PS256', 'sha256');
  const sig = await meta.sign(privateKey, Buffer.from('m'));
  assert.equal(await meta.verify(publicKey, Buffer.from('m'), sig), true);
});

test('EdDSA (Ed25519) round-trip via factory', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const meta = eddsa();
  const sig = await meta.sign(privateKey, Buffer.from('m'));
  assert.equal(await meta.verify(publicKey, Buffer.from('m'), sig), true);
});
