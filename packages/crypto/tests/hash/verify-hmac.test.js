import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { verifyHmac, hmac } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('verifyHmac', () => {
  const secret = 'shhh';
  const data = 'payload';
  const sigHex = hmac(data, secret);

  it('returns true for a matching hex signature (default)', () => {
    assert.equal(verifyHmac(data, sigHex, secret), true);
  });

  it('returns false for a mismatched signature', () => {
    assert.equal(verifyHmac(data, sigHex, 'wrong-secret'), false);
  });

  it('returns false for tampered data', () => {
    assert.equal(verifyHmac('other', sigHex, secret), false);
  });

  it('accepts base64url encoded expected', () => {
    const sig = hmac(data, secret, { encoding: 'base64url' });
    assert.equal(verifyHmac(data, sig, secret, { encoding: 'base64url' }), true);
  });

  it('accepts Buffer expected regardless of encoding option', () => {
    const sig = hmac(data, secret, { encoding: 'buffer' });
    assert.equal(verifyHmac(data, sig, secret), true);
  });

  it('supports non-default algo (sha512)', () => {
    const sig = hmac(data, secret, { algo: 'sha512' });
    assert.equal(verifyHmac(data, sig, secret, { algo: 'sha512' }), true);
  });

  it('returns false on length mismatch instead of throwing', () => {
    assert.equal(verifyHmac(data, 'abcd', secret), false);
  });

  it('rejects invalid input types', () => {
    for (const bad of [null, undefined, 42, {}, []]) {
      assert.throws(
        () => verifyHmac(bad, sigHex, secret),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });
});
