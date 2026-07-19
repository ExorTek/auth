import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { numeric } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('numeric', () => {
  it('returns a string of exactly the requested length', () => {
    for (const len of [1, 4, 6, 8, 16, 32]) {
      const s = numeric(len);
      assert.equal(typeof s, 'string');
      assert.equal(s.length, len);
    }
  });

  it('only contains digits 0-9', () => {
    const s = numeric(2048);
    assert.match(s, /^[0-9]+$/);
  });

  it('preserves leading zeros (never coerces to number)', () => {
    // Over 2000 samples we expect ~200 leading zeros; verify at least one.
    let seenLeadingZero = false;
    for (let i = 0; i < 2000; i++) {
      if (numeric(4).startsWith('0')) {
        seenLeadingZero = true;
        break;
      }
    }
    assert.ok(seenLeadingZero, 'expected at least one leading-zero sample in 2000 tries');
  });

  it('produces a uniform distribution (bias-free rejection sampling)', () => {
    // Chi-squared-lite: draw 100_000 digits and ensure each appears within
    // 3% of the expected uniform frequency (10_000). Rejection sampling should
    // deliver a very tight bound; 3% is a comfortable margin for CI stability.
    const counts = new Array(10).fill(0);
    const s = numeric(100_000);
    for (const ch of s) {
      counts[ch.charCodeAt(0) - 48]++;
    }
    for (let d = 0; d < 10; d++) {
      const deviation = Math.abs(counts[d] - 10_000) / 10_000;
      assert.ok(deviation < 0.03, `digit ${d}: count=${counts[d]}, deviation=${deviation.toFixed(4)}`);
    }
  });

  it('produces unique values on successive calls', () => {
    const set = new Set(Array.from({ length: 1000 }, () => numeric(10)));
    assert.equal(set.size, 1000);
  });

  it('rejects length === 0', () => {
    assert.throws(
      () => numeric(0),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('rejects negative, non-integer and non-number lengths', () => {
    for (const bad of [-1, 1.5, NaN, Infinity, '6', null, undefined, {}]) {
      assert.throws(
        () => numeric(bad),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });
});
