import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { base58 } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

// Bitcoin base58 alphabet omits 0, O, I, l.
const BASE58_RE = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]*$/;

describe('random.base58', () => {
  it('returns a base58 string (no 0, O, I, l)', () => {
    const s = base58(1024);
    assert.match(s, BASE58_RE);
    assert.doesNotMatch(s, /[0OIl]/);
  });

  it('output length is roughly size * 1.365 (58 is not a power of two)', () => {
    // Sample many; median length for size=16 should land near 21-22 chars.
    let lengths = [];
    for (let i = 0; i < 200; i++) {
      lengths.push(base58(16).length);
    }
    lengths.sort();
    const median = lengths[Math.floor(lengths.length / 2)];
    assert.ok(median >= 20 && median <= 24, `median length ${median} outside expected range`);
  });

  it('accepts size === 0 and returns an empty string', () => {
    assert.equal(base58(0), '');
  });

  it('produces unique values on successive calls', () => {
    const set = new Set(Array.from({ length: 1000 }, () => base58(16)));
    assert.equal(set.size, 1000);
  });

  it('propagates CryptoError from bytes() on invalid input', () => {
    for (const bad of [-1, 1.5, NaN, '16', null, undefined]) {
      assert.throws(
        () => base58(bad),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });
});
