import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { hmac } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

// RFC 4231 test case 1: HMAC-SHA-256, key = 0x0b × 20, data = 'Hi There'.
const RFC_KEY = Buffer.alloc(20, 0x0b);
const RFC_DATA = 'Hi There';
const RFC_SHA256 = 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7';
const RFC_SHA512 =
  '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854';

describe('hmac', () => {
  it('produces the RFC 4231 SHA-256 test vector', () => {
    assert.equal(hmac(RFC_DATA, RFC_KEY), RFC_SHA256);
  });

  it('produces the RFC 4231 SHA-512 test vector', () => {
    assert.equal(hmac(RFC_DATA, RFC_KEY, { algo: 'sha512' }), RFC_SHA512);
  });

  it('is deterministic under the same key + data', () => {
    assert.equal(hmac('payload', 'secret'), hmac('payload', 'secret'));
  });

  it('changes when data changes', () => {
    assert.notEqual(hmac('a', 'k'), hmac('b', 'k'));
  });

  it('changes when key changes', () => {
    assert.notEqual(hmac('payload', 'k1'), hmac('payload', 'k2'));
  });

  it('accepts string and Buffer for both data and secret', () => {
    const a = hmac('hi', 'k');
    const b = hmac(Buffer.from('hi'), Buffer.from('k'));
    const c = hmac('hi', Buffer.from('k'));
    const d = hmac(Buffer.from('hi'), 'k');
    assert.equal(a, b);
    assert.equal(b, c);
    assert.equal(c, d);
  });

  it('honors the encoding option', () => {
    const hex = hmac('data', 'key');
    const b64u = hmac('data', 'key', { encoding: 'base64url' });
    assert.notEqual(hex, b64u);
    assert.deepEqual(Buffer.from(hex, 'hex'), Buffer.from(b64u, 'base64url'));
  });

  it('rejects non-string, non-buffer data', () => {
    for (const bad of [null, undefined, 42, {}, []]) {
      assert.throws(
        () => hmac(bad, 'k'),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  it('rejects non-string, non-buffer secret', () => {
    for (const bad of [null, undefined, 42, {}, []]) {
      assert.throws(
        () => hmac('data', bad),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  it('rejects unsupported algorithms', () => {
    assert.throws(
      () => hmac('data', 'key', { algo: 'blake2b' }),
      err => err instanceof CryptoError && err.code === ErrorCode.UNSUPPORTED_ALGORITHM,
    );
  });
});
