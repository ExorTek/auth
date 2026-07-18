import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { encode, decode } from '../../src/encode/hex.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('encode.hex.encode', () => {
  it('encodes a UTF-8 string as lowercase hex', () => {
    assert.equal(encode('hello'), '68656c6c6f');
    assert.equal(encode(''), '');
  });

  it('encodes a Buffer directly', () => {
    assert.equal(encode(Buffer.from([0xde, 0xad, 0xbe, 0xef])), 'deadbeef');
    assert.equal(encode(Buffer.from([0x00, 0xff, 0x10])), '00ff10');
  });

  it('accepts Uint8Array', () => {
    assert.equal(encode(new Uint8Array([0xde, 0xad, 0xbe, 0xef])), 'deadbeef');
  });

  it('output length is exactly twice the byte length', () => {
    for (let size = 0; size < 64; size++) {
      assert.equal(encode(Buffer.alloc(size)).length, size * 2);
    }
  });

  it('handles unicode strings', () => {
    assert.equal(decode(encode('café')).toString('utf8'), 'café');
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

describe('encode.hex.decode', () => {
  it('round-trips arbitrary byte sequences', () => {
    for (let size = 0; size < 64; size++) {
      const buf = Buffer.alloc(size, size);
      assert.deepEqual(decode(encode(buf)), buf);
    }
  });

  it('is case-insensitive', () => {
    assert.deepEqual(decode('DEADBEEF'), Buffer.from([0xde, 0xad, 0xbe, 0xef]));
    assert.deepEqual(decode('deadbeef'), Buffer.from([0xde, 0xad, 0xbe, 0xef]));
    assert.deepEqual(decode('DeAdBeEf'), Buffer.from([0xde, 0xad, 0xbe, 0xef]));
  });

  it('accepts the empty string', () => {
    assert.deepEqual(decode(''), Buffer.alloc(0));
  });

  it('rejects odd-length strings', () => {
    assert.throws(
      () => decode('abc'),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ENCODING,
    );
    assert.throws(
      () => decode('deadbee'),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ENCODING,
    );
  });

  it('rejects non-hex characters', () => {
    for (const bad of ['xyzz', 'gg', 'deadbeeg', '0x1234']) {
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
});
