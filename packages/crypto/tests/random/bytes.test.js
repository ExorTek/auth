import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { bytes } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('bytes', () => {
  it('returns a Buffer of the requested length', () => {
    const buf = bytes(32);
    assert.ok(Buffer.isBuffer(buf));
    assert.equal(buf.length, 32);
  });

  it('supports common key sizes (16, 24, 32, 64)', () => {
    for (const size of [16, 24, 32, 64]) {
      assert.equal(bytes(size).length, size);
    }
  });

  it('accepts size === 0 and returns an empty Buffer', () => {
    const buf = bytes(0);
    assert.ok(Buffer.isBuffer(buf));
    assert.equal(buf.length, 0);
  });

  it('produces unique values on successive calls', () => {
    const set = new Set(Array.from({ length: 1000 }, () => bytes(32).toString('hex')));
    assert.equal(set.size, 1000, 'expected 1000 distinct random buffers');
  });

  it('produces byte distributions across the full 0–255 range', () => {
    // Smoke check — 4096 random bytes should hit >200 of the 256 possible values.
    const buf = bytes(4096);
    const seen = new Set(buf);
    assert.ok(seen.size > 200, `expected wide distribution, got ${seen.size} distinct values`);
  });

  it('rejects negative sizes', () => {
    assert.throws(
      () => bytes(-1),
      err => err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('rejects non-integer sizes', () => {
    assert.throws(
      () => bytes(1.5),
      err => err.code === 'INVALID_ARGUMENT' || err instanceof CryptoError,
    );
    assert.throws(
      () => bytes(NaN),
      err => err.code === 'INVALID_ARGUMENT' || err instanceof CryptoError,
    );
    assert.throws(
      () => bytes(Infinity),
      err => err.code === 'INVALID_ARGUMENT' || err instanceof CryptoError,
    );
  });

  it('rejects non-number sizes', () => {
    assert.throws(
      () => bytes('16'),
      err => err.code === 'INVALID_ARGUMENT' || err instanceof CryptoError,
    );
    assert.throws(
      () => bytes(null),
      err => err.code === 'INVALID_ARGUMENT' || err instanceof CryptoError,
    );
    assert.throws(
      () => bytes(undefined),
      err => err.code === 'INVALID_ARGUMENT' || err instanceof CryptoError,
    );
    assert.throws(
      () => bytes({}),
      err => err.code === 'INVALID_ARGUMENT' || err instanceof CryptoError,
    );
    assert.throws(
      () => bytes([]),
      err => err.code === 'INVALID_ARGUMENT' || err instanceof CryptoError,
    );
  });

  it('carries the INVALID_ARGUMENT code on every rejection', () => {
    for (const bad of [-1, 1.5, NaN, '16', null, undefined]) {
      assert.throws(
        () => bytes(bad),
        err => {
          assert.equal(err.code, ErrorCode.INVALID_ARGUMENT);
          return true;
        },
      );
    }
  });
});
