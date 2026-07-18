import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { base64 } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

describe('random.base64', () => {
  it('returns a padded base64 string of the expected length', () => {
    // N bytes → 4 * ceil(N / 3) chars with `=` padding.
    for (const [size, len] of [
      [1, 4],
      [2, 4],
      [3, 4],
      [16, 24],
      [32, 44],
      [48, 64],
    ]) {
      const s = base64(size);
      assert.equal(typeof s, 'string');
      assert.equal(s.length, len, `size=${size}: expected ${len}, got ${s.length}`);
    }
  });

  it('only contains standard base64 characters', () => {
    assert.match(base64(1024), BASE64_RE);
  });

  it('may include `+`, `/` and `=` — this is the URL-unsafe variant by design', () => {
    // Over many samples we should see the non-URL-safe alphabet used at least once.
    let sawUrlUnsafe = false;
    for (let i = 0; i < 500; i++) {
      if (/[+/=]/.test(base64(24))) {
        sawUrlUnsafe = true;
        break;
      }
    }
    assert.ok(sawUrlUnsafe, 'expected `+`, `/` or `=` in at least one 500-sample run');
  });

  it('accepts size === 0 and returns an empty string', () => {
    assert.equal(base64(0), '');
  });

  it('produces unique values on successive calls', () => {
    const set = new Set(Array.from({ length: 1000 }, () => base64(16)));
    assert.equal(set.size, 1000);
  });

  it('propagates CryptoError from bytes() on invalid input', () => {
    for (const bad of [-1, 1.5, NaN, '16', null, undefined]) {
      assert.throws(
        () => base64(bad),
        err => err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });
});
