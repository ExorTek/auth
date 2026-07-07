import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { encode } from '../../src/encode/base58.js';
import { decode } from '../../src/encode/base58.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

// Bitcoin base58 alphabet omits 0, O, I, l.
const BASE58_RE = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]*$/;

describe('encode.base58', () => {
  it('empty buffer → empty string', () => {
    assert.equal(encode(Buffer.alloc(0)), '');
  });

  it('accepts string, Buffer, and Uint8Array', () => {
    const bytes = Buffer.from('hello');
    const fromStr = encode('hello');
    const fromBuf = encode(bytes);
    const fromU8 = encode(new Uint8Array(bytes));
    assert.equal(fromStr, fromBuf);
    assert.equal(fromU8, fromBuf);
  });

  it("'hello' round-trips through encode/decode", () => {
    const encoded = encode('hello');
    assert.match(encoded, BASE58_RE);
    assert.equal(decode(encoded).toString('utf8'), 'hello');
  });

  it('round-trips arbitrary byte buffers', () => {
    for (const size of [1, 7, 16, 32, 64, 100]) {
      const buf = Buffer.alloc(size);
      for (let i = 0; i < size; i++) {
        buf[i] = (i * 37) & 0xff;
      }
      assert.deepEqual(decode(encode(buf)), buf);
    }
  });

  it('preserves leading zero bytes as leading 1s', () => {
    // 0x00 0x00 0xff → two leading '1's + base58('ff').
    assert.equal(encode(Buffer.from([0x00, 0x00, 0xff])), '115Q');
    assert.deepEqual(decode('115Q'), Buffer.from([0x00, 0x00, 0xff]));
    // A buffer that is *all* zeros → all 1s of the same length.
    assert.equal(encode(Buffer.alloc(4)), '1111');
    assert.deepEqual(decode('1111'), Buffer.alloc(4));
  });

  it('output is limited to the base58 alphabet', () => {
    for (const size of [1, 10, 100, 1000]) {
      const buf = Buffer.alloc(size);
      for (let i = 0; i < size; i++) {
        buf[i] = i & 0xff;
      }
      assert.match(encode(buf), BASE58_RE);
    }
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

describe('decode.base58', () => {
  it('empty string → empty buffer', () => {
    assert.deepEqual(decode(''), Buffer.alloc(0));
  });

  it('rejects look-alike characters (0, O, I, l)', () => {
    for (const bad of ['0abc', 'O123', 'I234', 'lmno']) {
      assert.throws(
        () => decode(bad),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ENCODING,
      );
    }
  });

  it('rejects non-string input', () => {
    for (const bad of [null, undefined, 42, Buffer.from('x')]) {
      assert.throws(
        () => decode(bad),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  it('reports the offending character and index', () => {
    try {
      decode('abc0xyz');
    } catch (err) {
      assert.equal(err.code, ErrorCode.INVALID_ENCODING);
      assert.match(err.message, /'0'/);
      assert.match(err.message, /index 3/);
      return;
    }
    assert.fail('expected throw');
  });
});
