import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { signValue, unsignValue } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

const SECRET = 'shhh-do-not-share';

describe('signValue / unsignValue', () => {
  it('round-trips a simple value', () => {
    const signed = signValue('user:42', SECRET);
    assert.equal(unsignValue(signed, SECRET), 'user:42');
  });

  it('output has the "<value>.<mac>" shape', () => {
    const signed = signValue('user:42', SECRET);
    const [value, mac] = signed.split('.');
    assert.equal(value, 'user:42');
    assert.match(mac, /^[A-Za-z0-9_-]+$/);
  });

  it('is deterministic for the same secret + value', () => {
    assert.equal(signValue('x', SECRET), signValue('x', SECRET));
  });

  it('produces different macs for different secrets', () => {
    assert.notEqual(signValue('x', 'a'), signValue('x', 'b'));
  });

  it('accepts Buffer secret', () => {
    const secret = Buffer.from('binary-secret');
    const signed = signValue('x', secret);
    assert.equal(unsignValue(signed, secret), 'x');
  });

  it('supports sha384 and sha512', () => {
    for (const algo of ['sha384', 'sha512']) {
      const signed = signValue('x', SECRET, { algo });
      assert.equal(unsignValue(signed, SECRET, { algo }), 'x');
    }
  });

  it('mac length grows with algo strength', () => {
    // base64url of 32 / 48 / 64 raw bytes = 43 / 64 / 86 chars (no padding).
    const macLen = algo => signValue('x', SECRET, { algo }).split('.')[1].length;
    assert.equal(macLen('sha256'), 43);
    assert.equal(macLen('sha384'), 64);
    assert.equal(macLen('sha512'), 86);
  });

  it('rejects a value containing a "."', () => {
    assert.throws(
      () => signValue('a.b', SECRET),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('rejects a non-string value', () => {
    for (const bad of [null, undefined, 42, {}, Buffer.from('x')]) {
      assert.throws(
        () => signValue(bad, SECRET),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  it('rejects an unsupported algo at sign time', () => {
    assert.throws(
      () => signValue('x', SECRET, { algo: 'md5' }),
      err => err instanceof CryptoError && err.code === ErrorCode.UNSUPPORTED_ALGORITHM,
    );
  });
});

describe('unsignValue — negative cases return null', () => {
  it('null for wrong secret', () => {
    const signed = signValue('x', 'right');
    assert.equal(unsignValue(signed, 'wrong'), null);
  });

  it('null for tampered value', () => {
    const signed = signValue('user:42', SECRET);
    const tampered = 'user:99' + signed.slice('user:42'.length);
    assert.equal(unsignValue(tampered, SECRET), null);
  });

  it('null for tampered mac', () => {
    const signed = signValue('user:42', SECRET);
    // Flip the last char of the mac
    const flipped = signed.slice(0, -1) + (signed.at(-1) === 'A' ? 'B' : 'A');
    assert.equal(unsignValue(flipped, SECRET), null);
  });

  it('null for a mac produced with a different algo', () => {
    const signed = signValue('x', SECRET, { algo: 'sha512' });
    assert.equal(unsignValue(signed, SECRET, { algo: 'sha256' }), null);
  });

  it('null for missing separator', () => {
    assert.equal(unsignValue('nodothere', SECRET), null);
  });

  it('null for empty value part', () => {
    assert.equal(unsignValue('.abc', SECRET), null);
  });

  it('null for empty mac part', () => {
    assert.equal(unsignValue('abc.', SECRET), null);
  });

  it('null for unsupported algo option', () => {
    const signed = signValue('x', SECRET);
    assert.equal(unsignValue(signed, SECRET, { algo: 'md5' }), null);
  });
});
