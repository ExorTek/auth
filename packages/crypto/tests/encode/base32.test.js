import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { encode, decode } from '../../src/encode/base32.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('encode.base32.encode', () => {
  it('matches RFC 4648 §10 test vectors (unpadded default)', () => {
    // From RFC 4648, minus trailing padding.
    assert.equal(encode(''), '');
    assert.equal(encode('f'), 'MY');
    assert.equal(encode('fo'), 'MZXQ');
    assert.equal(encode('foo'), 'MZXW6');
    assert.equal(encode('foob'), 'MZXW6YQ');
    assert.equal(encode('fooba'), 'MZXW6YTB');
    assert.equal(encode('foobar'), 'MZXW6YTBOI');
  });

  it('emits `=` padding when requested (RFC-strict form)', () => {
    assert.equal(encode('f', { padding: true }), 'MY======');
    assert.equal(encode('fo', { padding: true }), 'MZXQ====');
    assert.equal(encode('foo', { padding: true }), 'MZXW6===');
    assert.equal(encode('foob', { padding: true }), 'MZXW6YQ=');
    assert.equal(encode('fooba', { padding: true }), 'MZXW6YTB');
    assert.equal(encode('foobar', { padding: true }), 'MZXW6YTBOI======');
  });

  it("encodes 'Hello' to 'JBSWY3DP' (5 bytes → 8 chars, no padding)", () => {
    assert.equal(encode('Hello'), 'JBSWY3DP');
  });

  it('accepts Buffer and Uint8Array input', () => {
    assert.equal(encode(Buffer.from([0xff, 0x00])), '74AA');
    assert.equal(encode(new Uint8Array([0xff, 0x00])), '74AA');
  });

  it('only emits characters from the RFC 4648 §6 alphabet', () => {
    const s = encode(Buffer.alloc(256, 0xab));
    assert.match(s, /^[A-Z2-7]+$/);
  });

  it('rejects non-string, non-buffer input', () => {
    for (const bad of [null, undefined, 42, {}, []]) {
      assert.throws(
        () => encode(bad),
        err => err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });
});

describe('encode.base32.decode', () => {
  it('round-trips arbitrary byte sequences', () => {
    for (let size = 0; size < 64; size++) {
      const buf = Buffer.alloc(size, size);
      assert.deepEqual(decode(encode(buf)), buf);
    }
  });

  it('matches RFC 4648 §10 test vectors', () => {
    assert.equal(decode('MY').toString('utf8'), 'f');
    assert.equal(decode('MZXQ').toString('utf8'), 'fo');
    assert.equal(decode('MZXW6').toString('utf8'), 'foo');
    assert.equal(decode('MZXW6YQ').toString('utf8'), 'foob');
    assert.equal(decode('MZXW6YTB').toString('utf8'), 'fooba');
    assert.equal(decode('MZXW6YTBOI').toString('utf8'), 'foobar');
  });

  it('accepts padded and unpadded input', () => {
    assert.deepEqual(decode('MY======'), Buffer.from('f'));
    assert.deepEqual(decode('MY'), Buffer.from('f'));
  });

  it('is case-insensitive', () => {
    assert.deepEqual(decode('jbswy3dp'), Buffer.from('Hello'));
    assert.deepEqual(decode('JbSwY3dP'), Buffer.from('Hello'));
  });

  it('accepts empty and whitespace-free strings only', () => {
    assert.deepEqual(decode(''), Buffer.alloc(0));
  });

  it('rejects non-alphabet characters', () => {
    for (const bad of ['MZ1XW', 'MZ0XW', 'MZ8XW', 'MZ9XW', 'JB SWY', 'JB-SWY']) {
      assert.throws(
        () => decode(bad),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ENCODING,
      );
    }
  });

  it('rejects non-string input', () => {
    for (const bad of [null, undefined, 42, Buffer.from('x'), {}, []]) {
      assert.throws(
        () => decode(bad),
        err => err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  it('decodes TOTP-style secrets (unpadded) for hmac input', async () => {
    // Google Authenticator format: 16-char (80-bit) shared secret.
    const secret = 'JBSWY3DPEHPK3PXP';
    const key = decode(secret);
    assert.equal(key.length, 10); // 80 bits = 10 bytes
  });
});
