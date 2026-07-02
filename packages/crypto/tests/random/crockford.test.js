import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { crockford } from '../../src/random/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

// 32 chars: 0-9 A-H J K M N P-T V-Z (no I, L, O, U)
const CROCKFORD_RE = /^[0-9A-HJKMNP-TV-Z]*$/;

describe('random.crockford', () => {
  it('returns a Crockford base32 string of ceil(size * 8 / 5) chars', () => {
    for (const [size, len] of [[1, 2], [5, 8], [10, 16], [16, 26], [20, 32]]) {
      const s = crockford(size);
      assert.equal(typeof s, 'string');
      assert.equal(s.length, len, `size=${size}: expected ${len}, got ${s.length}`);
    }
  });

  it('only contains Crockford characters (no I, L, O, U)', () => {
    const s = crockford(2048);
    assert.match(s, CROCKFORD_RE);
    assert.doesNotMatch(s, /[ILOU]/);
  });

  it('accepts size === 0 and returns an empty string', () => {
    assert.equal(crockford(0), '');
  });

  it('produces unique values on successive calls', () => {
    const set = new Set(Array.from({ length: 1000 }, () => crockford(10)));
    assert.equal(set.size, 1000);
  });

  it('propagates CryptoError from bytes() on invalid input', () => {
    for (const bad of [-1, 1.5, NaN, '16', null, undefined]) {
      assert.throws(
        () => crockford(bad),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });
});
