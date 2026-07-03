import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { pbkdf2, SUPPORTED_PBKDF2_HASHES } from '../../src/hash/pbkdf2.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('pbkdf2', () => {
  const salt = Buffer.from('0123456789abcdef', 'utf8');

  it('returns a Buffer of the requested length by default', async () => {
    const key = await pbkdf2('passphrase', { salt, iterations: 1000 });
    assert.ok(Buffer.isBuffer(key));
    assert.equal(key.length, 32);
  });

  it('is deterministic under the same (password, salt, iterations, keyLength, digest) tuple', async () => {
    const opts = { salt, iterations: 1000, keyLength: 32, digest: 'sha256' };
    const a = await pbkdf2('pass', opts);
    const b = await pbkdf2('pass', opts);
    assert.deepEqual(a, b);
  });

  it('produces different keys for different salts', async () => {
    const a = await pbkdf2('pass', { salt: Buffer.from('a'.repeat(16)), iterations: 1000 });
    const b = await pbkdf2('pass', { salt: Buffer.from('b'.repeat(16)), iterations: 1000 });
    assert.notDeepEqual(a, b);
  });

  it('produces different keys for different passwords', async () => {
    const a = await pbkdf2('pass-a', { salt, iterations: 1000 });
    const b = await pbkdf2('pass-b', { salt, iterations: 1000 });
    assert.notDeepEqual(a, b);
  });

  it('honors keyLength option', async () => {
    for (const keyLength of [16, 32, 64, 128]) {
      const key = await pbkdf2('pass', { salt, iterations: 1000, keyLength });
      assert.equal(key.length, keyLength);
    }
  });

  it('honors encoding option', async () => {
    const hex = await pbkdf2('pass', { salt, iterations: 1000, encoding: 'hex' });
    const b64u = await pbkdf2('pass', { salt, iterations: 1000, encoding: 'base64url' });
    const buf = await pbkdf2('pass', { salt, iterations: 1000, encoding: 'buffer' });
    assert.equal(typeof hex, 'string');
    assert.equal(typeof b64u, 'string');
    assert.ok(Buffer.isBuffer(buf));
    assert.deepEqual(Buffer.from(hex, 'hex'), buf);
    assert.deepEqual(Buffer.from(b64u, 'base64url'), buf);
  });

  it('supports each documented digest', async () => {
    for (const digest of SUPPORTED_PBKDF2_HASHES) {
      const key = await pbkdf2('pass', { salt, iterations: 1000, digest });
      assert.equal(key.length, 32);
    }
  });

  it('accepts string or Buffer for both password and salt', async () => {
    const a = await pbkdf2('pass', { salt: 'saltysalt', iterations: 1000 });
    const b = await pbkdf2(Buffer.from('pass'), { salt: Buffer.from('saltysalt'), iterations: 1000 });
    assert.deepEqual(a, b);
  });

  it('requires salt', async () => {
    await assert.rejects(
      () => pbkdf2('pass'),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
    await assert.rejects(
      () => pbkdf2('pass', {}),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('rejects unsupported digest', async () => {
    await assert.rejects(
      () => pbkdf2('pass', { salt, digest: 'md5' }),
      err => err instanceof CryptoError && err.code === ErrorCode.UNSUPPORTED_ALGORITHM,
    );
  });

  it('rejects non-positive iterations and keyLength', async () => {
    await assert.rejects(
      () => pbkdf2('pass', { salt, iterations: 0 }),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
    await assert.rejects(
      () => pbkdf2('pass', { salt, keyLength: -1 }),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });
});
