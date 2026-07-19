import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { concat, xor, wipe, equal } from '../../src/binary/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('binary.concat', () => {
  it('concatenates strings and Buffers', () => {
    const r = concat('user:', '42', Buffer.from([0x00]));
    const expected = Buffer.concat([Buffer.from('user:42', 'utf8'), Buffer.from([0x00])]);
    assert.deepEqual(r, expected);
  });

  it('handles empty and single-part concat', () => {
    assert.deepEqual(concat(), Buffer.alloc(0));
    assert.deepEqual(concat('x'), Buffer.from('x'));
  });

  it('rejects non-string, non-buffer parts', () => {
    assert.throws(
      () => concat('ok', 42),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });
});

describe('binary.xor', () => {
  it('XORs equal-length buffers', () => {
    assert.deepEqual(xor(Buffer.from([0xff, 0x00]), Buffer.from([0x0f, 0xff])), Buffer.from([0xf0, 0xff]));
  });

  it('is symmetric — xor twice with the same mask recovers the plaintext', () => {
    const mask = Buffer.from('some mask bytes.');
    const plain = Buffer.from('secret message !');
    assert.equal(mask.length, plain.length, 'test precondition: equal lengths');
    assert.deepEqual(xor(xor(plain, mask), mask), plain);
  });

  it('accepts string inputs', () => {
    assert.deepEqual(xor('ab', 'cd'), Buffer.from([0x02, 0x06])); // 'a'^'c', 'b'^'d'
  });

  it('rejects mismatched lengths', () => {
    assert.throws(
      () => xor(Buffer.from([1, 2, 3]), Buffer.from([1, 2])),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });
});

describe('binary.wipe', () => {
  it('zeros a Buffer in place', () => {
    const buf = Buffer.from([1, 2, 3, 4]);
    wipe(buf);
    assert.deepEqual(buf, Buffer.from([0, 0, 0, 0]));
  });

  it('accepts Uint8Array', () => {
    const u = new Uint8Array([1, 2, 3]);
    wipe(u);
    assert.deepEqual(Array.from(u), [0, 0, 0]);
  });

  it('rejects non-buffer input', () => {
    for (const bad of [null, undefined, 'x', 42, {}, []]) {
      assert.throws(
        () => wipe(bad),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });
});

describe('binary.equal', () => {
  it('returns true for equal byte inputs', () => {
    assert.equal(equal('hello', 'hello'), true);
    assert.equal(equal(Buffer.from([1, 2, 3]), Buffer.from([1, 2, 3])), true);
  });

  it('returns false for different content', () => {
    assert.equal(equal('hello', 'world'), false);
  });

  it('returns false (no throw) for length mismatch', () => {
    assert.equal(equal('a', 'ab'), false);
  });

  it('rejects invalid input types', () => {
    for (const bad of [null, undefined, 42, {}, []]) {
      assert.throws(
        () => equal(bad, 'x'),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });
});
