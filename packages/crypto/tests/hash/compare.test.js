import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { compare } from '../../src/index.js';
import { hash } from '../../src/index.js';
import { hmac } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('compare', () => {
  it('returns true for equal strings', () => {
    assert.equal(compare('hello', 'hello'), true);
  });

  it('returns false for unequal strings of the same length', () => {
    assert.equal(compare('hello', 'world'), false);
  });

  it('returns false for strings of different lengths (no throw)', () => {
    assert.equal(compare('a', 'ab'), false);
    assert.equal(compare('', 'x'), false);
  });

  it('returns true for equal Buffers', () => {
    const a = Buffer.from([1, 2, 3, 4]);
    const b = Buffer.from([1, 2, 3, 4]);
    assert.equal(compare(a, b), true);
  });

  it('returns false for Buffers with the same length but different content', () => {
    assert.equal(compare(Buffer.from([1, 2, 3]), Buffer.from([1, 2, 4])), false);
  });

  it('cross-compares strings and Buffers correctly', () => {
    assert.equal(compare('hello', Buffer.from('hello', 'utf8')), true);
    assert.equal(compare(Buffer.from('hello'), 'hello'), true);
    assert.equal(compare('hello', Buffer.from('world', 'utf8')), false);
  });

  it('works with real hash digests', () => {
    const stored = hash('super-secret');
    assert.equal(compare(hash('super-secret'), stored), true);
    assert.equal(compare(hash('wrong-guess'), stored), false);
  });

  it('works with HMAC signatures', () => {
    const sig = hmac('payload', 'key');
    assert.equal(compare(sig, hmac('payload', 'key')), true);
    assert.equal(compare(sig, hmac('payload', 'wrong-key')), false);
  });

  it('handles empty inputs', () => {
    assert.equal(compare('', ''), true);
    assert.equal(compare(Buffer.alloc(0), Buffer.alloc(0)), true);
  });

  it('accepts Uint8Array', () => {
    assert.equal(compare(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])), true);
    assert.equal(compare(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])), false);
  });

  it('rejects non-string, non-buffer inputs', () => {
    for (const bad of [null, undefined, 42, {}, []]) {
      assert.throws(
        () => compare(bad, 'x'),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
      assert.throws(
        () => compare('x', bad),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });
});
