import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { token } from '../../src/index.js';
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
      (err) => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
    assert.throws(() => token(16, { prefix: null }), (err) => err instanceof CryptoError);
    assert.throws(() => token(16, { prefix: {} }), (err) => err instanceof CryptoError);
  });

  it('rejects a non-string separator', () => {
    assert.throws(
      () => token(16, { prefix: 'usr', separator: 42 }),
      (err) => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('rejects non-object options', () => {
    assert.throws(() => token(16, 'usr'), (err) => err instanceof CryptoError);
    assert.throws(() => token(16, null), (err) => err instanceof CryptoError);
    assert.throws(() => token(16, 42), (err) => err instanceof CryptoError);
  });

  it('propagates CryptoError from bytes() on invalid size', () => {
    for (const bad of [-1, 1.5, NaN, '16', null, undefined]) {
      assert.throws(
        () => token(bad),
        (err) => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  it('empty-string prefix behaves as no prefix (no separator emitted)', () => {
    const t = token(16, { prefix: '' });
    assert.equal(t.length, 22);
    assert.doesNotMatch(t, /^_/, 'should not lead with the default separator');
  });

  it('allows arbitrary separator strings (multi-char)', () => {
    const t = token(16, { prefix: 'org', separator: '::' });
    assert.ok(t.startsWith('org::'));
  });
});
