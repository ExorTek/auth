import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { encode, decode } from '../../src/encode/crockford.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

// Crockford alphabet omits I, L, O, U (and profanity concerns).
const CROCKFORD_RE = /^[0-9A-HJKMNP-TV-Z]*$/;

describe('encode.crockford', () => {
  it('empty buffer → empty string', () => {
    assert.equal(encode(Buffer.alloc(0)), '');
  });

  it('accepts string, Buffer, and Uint8Array', () => {
    const bytes = Buffer.from('hello');
    assert.equal(encode('hello'), encode(bytes));
    assert.equal(encode(new Uint8Array(bytes)), encode(bytes));
  });

  it('output stays within the Crockford alphabet', () => {
    for (const size of [1, 10, 100, 1000]) {
      const buf = Buffer.alloc(size);
      for (let i = 0; i < size; i++) {
        buf[i] = i & 0xff;
      }
      assert.match(encode(buf), CROCKFORD_RE);
    }
  });

  it('encodes to ceil(size * 8 / 5) chars', () => {
    // RFC 4648 §6 bit-window packing — size bytes → ceil(size*8/5) chars.
    for (const [size, len] of [
      [1, 2],
      [2, 4],
      [5, 8],
      [10, 16],
      [16, 26],
    ]) {
      assert.equal(encode(Buffer.alloc(size)).length, len);
    }
  });

  it('round-trips arbitrary buffers', () => {
    for (const size of [1, 5, 7, 16, 32, 64, 100]) {
      const buf = Buffer.alloc(size);
      for (let i = 0; i < size; i++) {
        buf[i] = (i * 37) & 0xff;
      }
      // Round-trip byte content, but decode returns floor(nchars*5/8) bytes —
      // for non-aligned inputs the last 1–4 pad bits are dropped. The first
      // `size` bytes should still match for aligned sizes; for non-aligned
      // sizes we compare only the recoverable prefix.
      const encoded = encode(buf);
      const back = decode(encoded);
      const recoverable = Math.floor((encoded.length * 5) / 8);
      assert.deepEqual(back.subarray(0, recoverable), buf.subarray(0, recoverable));
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

describe('decode.crockford', () => {
  it('empty string → empty buffer', () => {
    assert.deepEqual(decode(''), Buffer.alloc(0));
  });

  it('is case-insensitive', () => {
    const buf = Buffer.from('hello');
    const upper = encode(buf);
    assert.deepEqual(decode(upper.toLowerCase()), decode(upper));
  });

  it("treats 'I' and 'L' as '1'", () => {
    // '1' encodes to itself; 'I' and 'L' should decode identically.
    assert.deepEqual(decode('11111111'), decode('IIIIIIII'));
    assert.deepEqual(decode('11111111'), decode('LLLLLLLL'));
    assert.deepEqual(decode('11111111'), decode('iiiiiiii'));
    assert.deepEqual(decode('11111111'), decode('llllllll'));
  });

  it("treats 'O' as '0'", () => {
    assert.deepEqual(decode('00000000'), decode('OOOOOOOO'));
    assert.deepEqual(decode('00000000'), decode('oooooooo'));
  });

  it("rejects 'U' and other outside-alphabet characters", () => {
    for (const bad of ['UUUU', '@ABC', 'ABC$', 'abc!']) {
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
      decode('ABCU');
    } catch (err) {
      assert.equal(err.code, ErrorCode.INVALID_ENCODING);
      assert.match(err.message, /'U'/);
      assert.match(err.message, /index 3/);
      return;
    }
    assert.fail('expected throw');
  });
});
