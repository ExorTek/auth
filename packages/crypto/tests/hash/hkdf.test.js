import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { hkdf, SUPPORTED_HKDF_HASHES } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('hkdf', () => {
  const ikm = Buffer.from('0b'.repeat(22), 'hex'); // RFC 5869 test vector IKM
  const salt = Buffer.from('000102030405060708090a0b0c', 'hex');
  const info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex');

  it('returns a Buffer by default', () => {
    const k = hkdf(ikm, { salt, info, length: 42 });
    assert.ok(Buffer.isBuffer(k));
    assert.equal(k.length, 42);
  });

  it('matches RFC 5869 Test Case 1', () => {
    // OKM from RFC 5869 §A.1
    const expected = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865';
    const k = hkdf(ikm, { salt, info, length: 42, hash: 'sha256', encoding: 'hex' });
    assert.equal(k, expected);
  });

  it('produces different outputs for different info values (domain separation)', () => {
    const a = hkdf(ikm, { salt, info: 'encryption', length: 32 });
    const b = hkdf(ikm, { salt, info: 'authentication', length: 32 });
    assert.notDeepEqual(a, b);
  });

  it('accepts empty salt and info (defaults)', () => {
    const k = hkdf(ikm, { length: 32 });
    assert.equal(k.length, 32);
  });

  it('honors encoding option', () => {
    const buf = hkdf(ikm, { salt, info, length: 32 });
    const hex = hkdf(ikm, { salt, info, length: 32, encoding: 'hex' });
    const b64u = hkdf(ikm, { salt, info, length: 32, encoding: 'base64url' });
    assert.deepEqual(Buffer.from(hex, 'hex'), buf);
    assert.deepEqual(Buffer.from(b64u, 'base64url'), buf);
  });

  it('supports each documented hash', () => {
    for (const hash of SUPPORTED_HKDF_HASHES) {
      const k = hkdf(ikm, { salt, info, length: 32, hash });
      assert.equal(k.length, 32);
    }
  });

  it('rejects invalid ikm', () => {
    for (const bad of [null, undefined, 42, {}, []]) {
      assert.throws(
        () => hkdf(bad, { length: 32 }),
        err => err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  it('rejects unsupported hash', () => {
    assert.throws(
      () => hkdf(ikm, { hash: 'md5', length: 32 }),
      err => err instanceof CryptoError && err.code === ErrorCode.UNSUPPORTED_ALGORITHM,
    );
  });

  it('rejects non-positive length', () => {
    assert.throws(
      () => hkdf(ikm, { length: 0 }),
      err => err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });
});
