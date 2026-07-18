import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createSecretKey, KeyObject } from 'node:crypto';

import { createKeyNormalizer } from '../src/normalize-key.js';

class TestError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.code = code;
    this.name = 'TestError';
  }
}
const ErrorCode = { INVALID_KEY: 'INVALID_KEY' };

const TABLE = {
  HS256: { family: 'HMAC', kty: 'oct', hmacMinBytes: 32 },
  RS256: { family: 'RSA', kty: 'RSA' },
  ES256: { family: 'ECDSA', kty: 'EC', curve: 'P-256' },
  EdDSA: { family: 'EdDSA', kty: 'OKP' },
};
const lookupAlg = alg => {
  if (!(alg in TABLE)) throw new TestError('UNSUPPORTED', `unknown ${alg}`);
  return TABLE[alg];
};

const N = createKeyNormalizer({ ErrorClass: TestError, ErrorCode, lookupAlg });

describe('createKeyNormalizer', () => {
  test('KeyObject secret passthrough for HMAC', async () => {
    const secret = createSecretKey(Buffer.alloc(32));
    const out = await N.normalizeKey(secret, 'HS256', 'sign');
    assert.equal(out, secret);
  });

  test('Buffer HMAC secret → KeyObject', async () => {
    const out = await N.normalizeKey(Buffer.alloc(32), 'HS256', 'sign');
    assert.ok(out instanceof KeyObject);
    assert.equal(out.type, 'secret');
  });

  test('Uint8Array HMAC secret → KeyObject', async () => {
    const out = await N.normalizeKey(new Uint8Array(32), 'HS256', 'verify');
    assert.ok(out instanceof KeyObject);
  });

  test('Buffer under hmacMinBytes throws INVALID_KEY', async () => {
    await assert.rejects(
      N.normalizeKey(Buffer.alloc(16), 'HS256', 'sign'),
      err => err.code === 'INVALID_KEY' && /at least 32 bytes/.test(err.message),
    );
  });

  test('Buffer for asymmetric alg throws', async () => {
    await assert.rejects(
      N.normalizeKey(Buffer.alloc(32), 'RS256', 'sign'),
      err => err.code === 'INVALID_KEY' && /HMAC-only/.test(err.message),
    );
  });

  test('JWK oct → HMAC KeyObject', async () => {
    const jwk = { kty: 'oct', k: Buffer.alloc(32).toString('base64url') };
    const out = await N.normalizeKey(jwk, 'HS256', 'sign');
    assert.equal(out.type, 'secret');
  });

  test('JWK kty mismatch rejects', async () => {
    await assert.rejects(
      N.normalizeKey({ kty: 'RSA' }, 'HS256', 'sign'),
      err => err.code === 'INVALID_KEY' && /kty=oct/.test(err.message),
    );
  });

  test('JWK EC curve mismatch rejects', async () => {
    await assert.rejects(
      N.normalizeKey({ kty: 'EC', crv: 'P-384' }, 'ES256', 'verify'),
      err => err.code === 'INVALID_KEY' && /crv=P-256/.test(err.message),
    );
  });

  test('JWK sign without "d" rejects', async () => {
    await assert.rejects(
      N.normalizeKey({ kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' }, 'ES256', 'sign'),
      err => err.code === 'INVALID_KEY' && /private JWK/.test(err.message),
    );
  });

  test('RSA KeyObject under 2048 bits rejects', async () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
    await assert.rejects(
      N.normalizeKey(privateKey, 'RS256', 'sign'),
      err => err.code === 'INVALID_KEY' && /2048 bits/.test(err.message),
    );
  });

  test('unknown shape rejects', async () => {
    await assert.rejects(
      N.normalizeKey(42, 'HS256', 'sign'),
      err => err.code === 'INVALID_KEY' && /expected KeyObject/.test(err.message),
    );
  });

  test('normalizeCore returns null for unknown shape (for wrapper packages)', async () => {
    const out = await N.normalizeCore('a PEM string', 'HS256', 'sign');
    assert.equal(out, null);
  });
});
