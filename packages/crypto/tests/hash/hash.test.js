import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { hash } from '../../src/hash/hash.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

// Well-known digests of 'hello' — RFC test vectors / OpenSSL confirmations.
const HELLO = {
  sha256: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
  sha384: '59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f',
  sha512:
    '9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043',
  sha1: 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',
  md5: '5d41402abc4b2a76b9719d911017c592',
};

describe('hash', () => {
  it('defaults to SHA-256 hex output', () => {
    assert.equal(hash('hello'), HELLO.sha256);
  });

  it('supports every listed algorithm with the correct known digest', () => {
    for (const [algo, digest] of Object.entries(HELLO)) {
      assert.equal(hash('hello', { algo }), digest, `algo=${algo}`);
    }
  });

  it('supports Buffer input', () => {
    assert.equal(hash(Buffer.from('hello')), HELLO.sha256);
  });

  it('supports Uint8Array input', () => {
    assert.equal(hash(new Uint8Array([104, 101, 108, 108, 111])), HELLO.sha256);
  });

  it('honors the encoding option', () => {
    const hex = hash('hello');
    const b64 = hash('hello', { encoding: 'base64' });
    const b64u = hash('hello', { encoding: 'base64url' });
    // Same digest bytes, different encoding — sizes differ.
    assert.notEqual(hex, b64);
    assert.notEqual(b64, b64u);
    // Round-trip via Buffer to confirm equivalence.
    assert.deepEqual(Buffer.from(hex, 'hex'), Buffer.from(b64, 'base64'));
    assert.deepEqual(Buffer.from(hex, 'hex'), Buffer.from(b64u, 'base64url'));
  });

  it("encoding: 'buffer' returns raw digest bytes", () => {
    const hex = hash('hello');
    const buf = hash('hello', { encoding: 'buffer' });
    assert.ok(Buffer.isBuffer(buf));
    assert.equal(buf.length, 32); // SHA-256 = 32 bytes
    assert.equal(buf.toString('hex'), hex);
  });

  it('is deterministic (same input → same output)', () => {
    assert.equal(hash('same data'), hash('same data'));
  });

  it('differs for different inputs', () => {
    assert.notEqual(hash('input-a'), hash('input-b'));
  });

  it('handles empty input', () => {
    // Well-known empty SHA-256.
    assert.equal(hash(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('rejects non-string, non-buffer data', () => {
    for (const bad of [null, undefined, 42, {}, []]) {
      assert.throws(
        () => hash(bad),
        (err) => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  it('rejects unsupported algorithms', () => {
    assert.throws(
      () => hash('hello', { algo: 'sha3' }),
      (err) => err instanceof CryptoError && err.code === ErrorCode.UNSUPPORTED_ALGORITHM,
    );
  });

  it('rejects invalid encoding', () => {
    assert.throws(
      () => hash('hello', { encoding: 'binary' }),
      (err) => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('rejects non-object options', () => {
    assert.throws(() => hash('hello', 'sha256'), (err) => err instanceof CryptoError);
    assert.throws(() => hash('hello', null), (err) => err instanceof CryptoError);
    assert.throws(() => hash('hello', []), (err) => err instanceof CryptoError);
  });
});
