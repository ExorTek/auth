import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { code } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('code', () => {
  it('returns a string of the pattern length', () => {
    assert.equal(code('XXXX').length, 4);
    assert.equal(code('####-####').length, 9);
    assert.equal(code('AAAA-####').length, 9);
  });

  it('X placeholder emits alphanumeric mixed case', () => {
    const s = code('X'.repeat(200));
    assert.match(s, /^[A-Za-z0-9]{200}$/);
  });

  it('# placeholder emits digits only', () => {
    const s = code('#'.repeat(200));
    assert.match(s, /^[0-9]{200}$/);
  });

  it('A placeholder emits uppercase letters only', () => {
    const s = code('A'.repeat(200));
    assert.match(s, /^[A-Z]{200}$/);
  });

  it('a placeholder emits lowercase letters only', () => {
    const s = code('a'.repeat(200));
    assert.match(s, /^[a-z]{200}$/);
  });

  it('non-placeholder characters are copied literally', () => {
    // Pattern indices: S(0) K(1) _(2) #(3) #(4) #(5) #(6) _(7) X(8) X(9) X(10) X(11)
    const s = code('SK_####_XXXX');
    assert.ok(s.startsWith('SK_'));
    assert.equal(s[7], '_');
    assert.match(s.slice(3, 7), /^[0-9]{4}$/);
    assert.match(s.slice(8, 12), /^[A-Za-z0-9]{4}$/);
  });

  it('preserves separator characters (dashes, spaces, dots)', () => {
    const s = code('###-###.###');
    assert.equal(s.length, 11);
    assert.equal(s[3], '-');
    assert.equal(s[7], '.');
    assert.match(s.replace(/[-.]/g, ''), /^[0-9]{9}$/);
  });

  it('produces unique values across many draws', () => {
    const set = new Set(Array.from({ length: 5000 }, () => code('XXX-XXX')));
    assert.ok(set.size > 4900, `expected near-unique draws, got ${set.size}`);
  });

  it('rejects a non-string pattern', () => {
    assert.throws(
      () => code(42),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
    assert.throws(
      () => code(null),
      err => err instanceof CryptoError,
    );
    assert.throws(
      () => code(undefined),
      err => err instanceof CryptoError,
    );
  });

  it('rejects an empty pattern', () => {
    assert.throws(
      () => code(''),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });
});
