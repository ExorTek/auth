import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { base64url } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

const URL_SAFE_RE = /^[A-Za-z0-9_-]*$/;

describe('base64url', () => {
  it('returns a URL-safe string of the expected length', () => {
    // base64 expands N bytes to ceil(N * 4 / 3), no padding.
    const cases = [
      [1, 2],
      [2, 3],
      [3, 4],
      [16, 22],
      [32, 43],
      [48, 64],
    ];
    for (const [size, expectedLen] of cases) {
      const s = base64url(size);
      assert.equal(typeof s, 'string');
      assert.equal(s.length, expectedLen, `size=${size}: expected len ${expectedLen}, got ${s.length}`);
    }
  });

  it('only contains URL-safe characters (A-Z, a-z, 0-9, -, _)', () => {
    const s = base64url(1024);
    assert.match(s, URL_SAFE_RE);
  });

  it('never contains `+`, `/` or `=` (standard base64 chars)', () => {
    // Generate many samples to catch any leak from the standard alphabet.
    for (let i = 0; i < 200; i++) {
      const s = base64url(48);
      assert.doesNotMatch(s, /[+/=]/, `illegal char in ${s}`);
    }
  });

  it('accepts size === 0 and returns an empty string', () => {
    assert.equal(base64url(0), '');
  });

  it('produces unique values on successive calls', () => {
    const set = new Set(Array.from({ length: 1000 }, () => base64url(16)));
    assert.equal(set.size, 1000);
  });

  it('propagates CryptoError from bytes() on invalid input', () => {
    for (const bad of [-1, 1.5, NaN, '16', null, undefined]) {
      assert.throws(
        () => base64url(bad),
        err => {
          assert.ok(err instanceof CryptoError);
          assert.equal(err.code, ErrorCode.INVALID_ARGUMENT);
          return true;
        },
      );
    }
  });
});
