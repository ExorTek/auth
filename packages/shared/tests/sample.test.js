import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { sampleAlphabet, sampleUint16Indices } from '../src/sample.js';

describe('sampleAlphabet', () => {
  test('returns a string of the requested length', () => {
    const s = sampleAlphabet('abcdef', 100);
    assert.equal(s.length, 100);
  });

  test('length === 0 returns empty string', () => {
    assert.equal(sampleAlphabet('abc', 0), '');
  });

  test('output only contains characters from the alphabet', () => {
    const alphabet = 'ABCDEFGH';
    const s = sampleAlphabet(alphabet, 1000);
    for (const ch of s) {
      assert.ok(alphabet.includes(ch), `unexpected character ${JSON.stringify(ch)}`);
    }
  });

  test('distribution is roughly uniform (chi-square light sanity)', () => {
    const alphabet = 'ABCDEFGH'; // 8 chars → expect n/8 each
    const n = 8000;
    const counts = new Map();
    for (const ch of sampleAlphabet(alphabet, n)) {
      counts.set(ch, (counts.get(ch) ?? 0) + 1);
    }
    // No bucket should be more than 25% off the expected mean —
    // extremely loose bound to avoid flakes but still catches a
    // bias-broken implementation.
    const expected = n / alphabet.length;
    for (const [ch, c] of counts) {
      assert.ok(Math.abs(c - expected) < expected * 0.25, `${ch}: ${c} outside 25% band of ${expected}`);
    }
  });

  test('rejects bad alphabet', () => {
    for (const bad of ['', 'x'.repeat(257), null, 42, {}]) {
      assert.throws(() => sampleAlphabet(bad, 10), /sampleAlphabet: alphabet must be a string/);
    }
  });

  test('rejects bad length', () => {
    for (const bad of [-1, 1.5, NaN, '10', null]) {
      assert.throws(() => sampleAlphabet('abc', bad), /sampleAlphabet: length must be/);
    }
  });
});

describe('sampleUint16Indices', () => {
  test('returns an array of the requested length', () => {
    const out = sampleUint16Indices(256, 50);
    assert.equal(out.length, 50);
  });

  test('every index is in [0, maxExclusive)', () => {
    const out = sampleUint16Indices(256, 500);
    for (const v of out) {
      assert.ok(v >= 0 && v < 256, `out-of-range index ${v}`);
      assert.ok(Number.isSafeInteger(v));
    }
  });

  test('count === 0 returns empty array', () => {
    assert.deepEqual(sampleUint16Indices(256, 0), []);
  });

  test('works at maxExclusive === 1 (degenerate — all zeros)', () => {
    const out = sampleUint16Indices(1, 10);
    assert.equal(out.length, 10);
    for (const v of out) assert.equal(v, 0);
  });

  test('works at maxExclusive === 65_536 (upper bound)', () => {
    const out = sampleUint16Indices(65_536, 5);
    assert.equal(out.length, 5);
    for (const v of out) assert.ok(v >= 0 && v < 65_536);
  });

  test('rejects bad maxExclusive', () => {
    for (const bad of [0, -1, 65_537, 1.5, NaN, '256']) {
      assert.throws(() => sampleUint16Indices(bad, 10), /sampleUint16Indices: maxExclusive/);
    }
  });

  test('rejects bad count', () => {
    for (const bad of [-1, 1.5, NaN, '10']) {
      assert.throws(() => sampleUint16Indices(256, bad), /sampleUint16Indices: count/);
    }
  });
});
