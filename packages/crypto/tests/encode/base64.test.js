import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { encode, decode } from '../../src/encode/base64.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('encode.base64.encode', () => {
  it('encodes a UTF-8 string with padding to a multiple of 4', () => {
    assert.equal(encode('hello'), 'aGVsbG8=');
    assert.equal(encode('hi'), 'aGk=');
    assert.equal(encode(''), '');
    assert.equal(encode('abcd'), 'YWJjZA==');
  });

  it('encodes a Buffer directly', () => {
    assert.equal(encode(Buffer.from([0xff, 0x00, 0xff])), '/wD/');
    assert.equal(encode(Buffer.from('hello')), 'aGVsbG8=');
  });

  it('accepts Uint8Array', () => {
    assert.equal(encode(new Uint8Array([0xff, 0x00, 0xff])), '/wD/');
  });

  it('handles unicode strings', () => {
    const s = encode('café ☕');
    assert.equal(decode(s).toString('utf8'), 'café ☕');
  });

  it('rejects non-string, non-buffer input', () => {
    for (const bad of [null, undefined, 42, {}, []]) {
      assert.throws(
        () => encode(bad),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });
});

describe('encode.base64.decode', () => {
  it('round-trips arbitrary byte sequences', () => {
    for (let size = 0; size < 64; size++) {
      const buf = Buffer.alloc(size, size);
      assert.deepEqual(decode(encode(buf)), buf);
    }
  });

  it('accepts both padded and unpadded input', () => {
    assert.deepEqual(decode('aGVsbG8='), Buffer.from('hello'));
    assert.deepEqual(decode('aGVsbG8'), Buffer.from('hello'));
    assert.deepEqual(decode('YWJjZA=='), Buffer.from('abcd'));
    assert.deepEqual(decode('YWJjZA'), Buffer.from('abcd'));
  });

  it('rejects strings containing base64url-only chars `-` or `_`', () => {
    assert.throws(
      () => decode('aB-_xy'),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ENCODING,
    );
  });

  it('rejects malformed strings', () => {
    for (const bad of ['!!!', 'hello world', 'aGVsbG8!!']) {
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
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });
});
