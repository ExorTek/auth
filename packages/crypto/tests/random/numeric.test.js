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
    // Pearson chi-squared over 1_000_000 digits (9 degrees of freedom). A
    // healthy generator stays under 42.6 with probability 1 - 1e-6, so this
    // essentially never flakes; plain `byte % 10` modulo bias (26/256 vs
    // 25/256 per digit) scores ≈ 365 and is caught every time. A per-digit
    // percentage bound cannot do both: 3% at 100k samples is only ~3σ and
    // failed on healthy runs.
    const N = 1_000_000;
    const counts = new Array(10).fill(0);
    const s = numeric(N);
    for (const ch of s) {
      counts[ch.charCodeAt(0) - 48]++;
    }
    const expected = N / 10;
    const chi2 = counts.reduce((sum, c) => sum + (c - expected) ** 2 / expected, 0);
    assert.ok(chi2 < 42.6, `chi-squared ${chi2.toFixed(1)} over counts ${counts.join(',')}`);
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
