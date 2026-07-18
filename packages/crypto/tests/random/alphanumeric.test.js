import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { alphanumeric } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('alphanumeric', () => {
  it('returns a string of exactly the requested length', () => {
    for (const len of [1, 8, 16, 21, 32, 64]) {
      const s = alphanumeric(len);
      assert.equal(typeof s, 'string');
      assert.equal(s.length, len);
    }
  });

  it('only contains [A-Za-z0-9]', () => {
    const s = alphanumeric(4096);
    assert.match(s, /^[A-Za-z0-9]+$/);
  });

  it('produces a roughly uniform distribution (bias-free rejection sampling)', () => {
    // 62 buckets × ~4000 samples each = 248_000 draws. The larger sample
    // tightens variance so the 15% deviation ceiling doesn't ride the flake
    // line: for N=4000 the standard deviation is ~63 (≈1.6%), so 15%
    // catches a broken RNG (bias ≥ ~9σ) with essentially zero false
    // positives on a healthy one.
    const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const counts = new Map(ALPHABET.split('').map(c => [c, 0]));
    const s = alphanumeric(248_000);
    for (const ch of s) {
      counts.set(ch, counts.get(ch) + 1);
    }
    for (const [ch, count] of counts) {
      const deviation = Math.abs(count - 4000) / 4000;
      assert.ok(deviation < 0.15, `char '${ch}': count=${count}, deviation=${deviation.toFixed(4)}`);
    }
  });

  it('produces unique values on successive calls', () => {
    const set = new Set(Array.from({ length: 1000 }, () => alphanumeric(21)));
    assert.equal(set.size, 1000);
  });

  it('rejects length === 0', () => {
    assert.throws(
      () => alphanumeric(0),
      err => err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('rejects negative, non-integer and non-number lengths', () => {
    for (const bad of [-1, 1.5, NaN, Infinity, '21', null, undefined, {}]) {
      assert.throws(
        () => alphanumeric(bad),
        err => err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });
});
