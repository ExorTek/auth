import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { token, TOKEN_ENCODINGS } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

const URL_SAFE_BODY = /^[A-Za-z0-9_-]+$/;

describe('token', () => {
  it('returns a bare base64url body when no prefix is set', () => {
    const t = token(32);
    assert.equal(typeof t, 'string');
    assert.equal(t.length, 43); // 32 bytes → 43 chars base64url
    assert.match(t, URL_SAFE_BODY);
  });

  it('accepts an empty options object', () => {
    const t = token(16, {});
    assert.equal(t.length, 22);
    assert.match(t, URL_SAFE_BODY);
  });

  it('prefixes the body with `<prefix>_<body>` by default', () => {
    const t = token(32, { prefix: 'usr' });
    assert.ok(t.startsWith('usr_'), `expected 'usr_' prefix, got ${t}`);
    const body = t.slice('usr_'.length);
    assert.equal(body.length, 43);
    assert.match(body, URL_SAFE_BODY);
  });

  it('honors a custom separator', () => {
    const t = token(32, { prefix: 'sk_live', separator: '-' });
    assert.ok(t.startsWith('sk_live-'));
  });

  it('produces unique bodies on successive calls', () => {
    const set = new Set(Array.from({ length: 1000 }, () => token(16, { prefix: 'usr' })));
    assert.equal(set.size, 1000);
  });

  it('rejects a non-string prefix', () => {
    assert.throws(
      () => token(16, { prefix: 123 }),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
    assert.throws(
      () => token(16, { prefix: null }),
      err => err instanceof CryptoError,
    );
    assert.throws(
      () => token(16, { prefix: {} }),
      err => err instanceof CryptoError,
    );
  });

  it('rejects a non-string separator', () => {
    assert.throws(
      () => token(16, { prefix: 'usr', separator: 42 }),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('rejects non-object options', () => {
    assert.throws(
      () => token(16, 'usr'),
      err => err instanceof CryptoError,
    );
    assert.throws(
      () => token(16, null),
      err => err instanceof CryptoError,
    );
    assert.throws(
      () => token(16, 42),
      err => err instanceof CryptoError,
    );
  });

  it('propagates CryptoError from bytes() on invalid size', () => {
    for (const bad of [-1, 1.5, NaN, '16', null, undefined]) {
      assert.throws(
        () => token(bad),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  it('empty-string prefix behaves as no prefix (no separator emitted)', () => {
    // With an empty prefix the output is pure base64url of 16 random
    // bytes — length 22 and no separator inserted. Note: `_` is a valid
    // base64url alphabet character (RFC 4648 §5), so we cannot assert
    // "does not start with '_'"; that would flake ~1.5% of runs.
    // The length is the only stable signal of "no separator emitted".
    const t = token(16, { prefix: '' });
    assert.equal(t.length, 22);
    assert.match(t, /^[A-Za-z0-9_-]+$/);
  });

  it('allows arbitrary separator strings (multi-char)', () => {
    const t = token(16, { prefix: 'org', separator: '::' });
    assert.ok(t.startsWith('org::'));
  });

  it('rejects an empty separator string', () => {
    assert.throws(
      () => token(16, { prefix: 'usr', separator: '' }),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });
});

describe('token — encodings', () => {
  it('exports TOKEN_ENCODINGS listing every supported encoding', () => {
    assert.deepEqual([...TOKEN_ENCODINGS].sort(), ['base58', 'base64', 'base64url', 'crockford', 'hex']);
  });

  it("encoding: 'hex' produces lowercase hex", () => {
    const t = token(8, { encoding: 'hex' });
    assert.equal(t.length, 16);
    assert.match(t, /^[0-9a-f]+$/);
  });

  it("encoding: 'base64' produces padded base64", () => {
    const t = token(16, { encoding: 'base64' });
    assert.equal(t.length, 24);
    assert.match(t, /^[A-Za-z0-9+/]+=*$/);
  });

  it("encoding: 'crockford' produces sortable Crockford base32", () => {
    const t = token(16, { encoding: 'crockford' });
    assert.equal(t.length, 26); // ceil(16 * 8 / 5)
    assert.match(t, /^[0-9A-HJKMNP-TV-Z]+$/);
  });

  it("encoding: 'base58' produces Bitcoin base58", () => {
    const t = token(16, { encoding: 'base58' });
    assert.match(t, /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/);
    assert.doesNotMatch(t, /[0OIl]/);
  });

  it('combines prefix + encoding', () => {
    const t = token(8, { prefix: 'ID', encoding: 'crockford' });
    assert.ok(t.startsWith('ID_'));
    const body = t.slice('ID_'.length);
    assert.equal(body.length, 13); // ceil(8 * 8 / 5)
  });

  it('rejects an unknown encoding', () => {
    assert.throws(
      () => token(16, { encoding: 'base32' }),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });
});
