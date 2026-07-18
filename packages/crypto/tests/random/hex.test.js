import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { hex } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

const HEX_RE = /^[0-9a-f]*$/;

describe('hex', () => {
  it('returns a string of length size * 2', () => {
    for (const size of [1, 8, 16, 32, 64]) {
      const s = hex(size);
      assert.equal(typeof s, 'string');
      assert.equal(s.length, size * 2);
    }
  });

  it('only contains lowercase hex characters', () => {
    const s = hex(1024);
    assert.match(s, HEX_RE);
  });

  it('accepts size === 0 and returns an empty string', () => {
    assert.equal(hex(0), '');
  });

  it('produces unique values on successive calls', () => {
    const set = new Set(Array.from({ length: 1000 }, () => hex(16)));
    assert.equal(set.size, 1000);
  });

  it('propagates CryptoError from bytes() on invalid input', () => {
    for (const bad of [-1, 1.5, NaN, '16', null, undefined]) {
      assert.throws(
        () => hex(bad),
        err => {
          assert.equal(err.code, ErrorCode.INVALID_ARGUMENT);
          return true;
        },
      );
    }
  });
});
