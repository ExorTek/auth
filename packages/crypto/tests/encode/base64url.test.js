import { describe, it } from 'node:test';
import { randomBytes } from 'node:crypto';
import assert from 'node:assert/strict';

import { encode } from '../../src/encode/base64url.js';
import { decode } from '../../src/encode/base64url.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('encode.base64url.encode', () => {
  it('encodes a UTF-8 string with no padding', () => {
    assert.equal(encode('hello'), 'aGVsbG8');
    assert.equal(encode('hi'), 'aGk');
    assert.equal(encode(''), '');
  });

  it('encodes a Buffer directly', () => {
    assert.equal(encode(Buffer.from([0xff, 0x00, 0xff])), '_wD_');
    assert.equal(encode(Buffer.from('hello')), 'aGVsbG8');
  });

  it('accepts Uint8Array', () => {
    assert.equal(encode(new Uint8Array([0xff, 0x00, 0xff])), '_wD_');
  });

  it('never emits `+`, `/` or `=`', () => {
    for (let i = 0; i < 500; i++) {
      const s = encode(Buffer.from([i & 0xff, (i >> 3) & 0xff, (i >> 5) & 0xff, 0xff, 0xfe]));
      assert.doesNotMatch(s, /[+/=]/, `illegal char in ${s}`);
    }
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

describe('encode.base64url.decode', () => {
  it('round-trips arbitrary byte sequences', () => {
    for (let size = 0; size < 64; size++) {
      const buf = Buffer.alloc(size, size);
      assert.deepEqual(decode(encode(buf)), buf);
    }
  });

  it('accepts padded input (as generous decoder)', () => {
    assert.deepEqual(decode('aGVsbG8='), Buffer.from('hello'));
    assert.deepEqual(decode('aGk='), Buffer.from('hi'));
  });

  it('rejects strings containing `+` or `/` (standard base64 alphabet)', () => {
    assert.throws(
      () => decode('aB+/xy'),
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

describe('encode.base64url canonicalisation', () => {
  it('decodes the canonical spelling, with or without padding', () => {
    assert.equal(decode('aGVsbG8').toString('utf8'), 'hello');
    assert.equal(decode('aGVsbG8=').toString('utf8'), 'hello');
  });

  it('rejects a non-canonical final character', () => {
    // All four of these decode to the same bytes under a permissive decoder,
    // because the unused low bits of the last character are ignored. Only
    // 'aGVsbG8' spells those bytes canonically.
    for (const variant of ['aGVsbG9', 'aGVsbG-', 'aGVsbG_']) {
      assert.throws(
        () => decode(variant),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ENCODING,
        `${variant} should not decode`,
      );
    }
  });

  it('round-trips every encode output back through decode', () => {
    for (let len = 0; len <= 24; len++) {
      const bytes = randomBytes(len);
      assert.deepEqual(decode(encode(bytes)), bytes, `length ${len}`);
    }
  });
});
