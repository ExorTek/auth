import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { encryptWithPassphrase, decryptWithPassphrase } from '../../src/cipher/passphrase.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

// Use a small iteration count throughout to keep the test suite fast; the
// pipeline is identical to production-grade values.
const FAST = { iterations: 1000 };

describe('cipher.encryptWithPassphrase / decryptWithPassphrase', () => {
  it('round-trips a UTF-8 string', async () => {
    const t = await encryptWithPassphrase('hello world', 'my-passphrase', FAST);
    const p = await decryptWithPassphrase(t, 'my-passphrase', FAST);
    assert.equal(p.toString('utf8'), 'hello world');
  });

  it('round-trips a Buffer', async () => {
    const src = Buffer.from([1, 2, 3, 4, 5]);
    const t = await encryptWithPassphrase(src, 'pw', FAST);
    const p = await decryptWithPassphrase(t, 'pw', FAST);
    assert.deepEqual(p, src);
  });

  it('produces a URL-safe base64url token by default', async () => {
    const t = await encryptWithPassphrase('x', 'pw', FAST);
    assert.match(t, /^[A-Za-z0-9_-]+$/);
  });

  it('supports hex encoding option', async () => {
    const t = await encryptWithPassphrase('x', 'pw', { ...FAST, encoding: 'hex' });
    assert.match(t, /^[0-9a-f]+$/);
    const p = await decryptWithPassphrase(t, 'pw', { ...FAST, encoding: 'hex' });
    assert.equal(p.toString('utf8'), 'x');
  });

  it('yields different tokens for the same plaintext + passphrase (fresh salt/iv)', async () => {
    const a = await encryptWithPassphrase('same', 'pw', FAST);
    const b = await encryptWithPassphrase('same', 'pw', FAST);
    assert.notEqual(a, b);
  });

  it('rejects wrong passphrase', async () => {
    const t = await encryptWithPassphrase('secret', 'right-pw', FAST);
    await assert.rejects(
      () => decryptWithPassphrase(t, 'wrong-pw', FAST),
      err => err instanceof CryptoError && err.code === ErrorCode.DECRYPT_FAILED,
    );
  });

  it('rejects mismatched iteration count at decrypt', async () => {
    const t = await encryptWithPassphrase('secret', 'pw', { iterations: 1000 });
    await assert.rejects(
      () => decryptWithPassphrase(t, 'pw', { iterations: 2000 }),
      err => err instanceof CryptoError && err.code === ErrorCode.DECRYPT_FAILED,
    );
  });

  it('rejects mismatched kdf digest at decrypt', async () => {
    const t = await encryptWithPassphrase('secret', 'pw', { ...FAST, kdf: 'sha256' });
    await assert.rejects(
      () => decryptWithPassphrase(t, 'pw', { ...FAST, kdf: 'sha512' }),
      err => err instanceof CryptoError && err.code === ErrorCode.DECRYPT_FAILED,
    );
  });

  it('rejects tampered ciphertext', async () => {
    const t = await encryptWithPassphrase('secret', 'pw', FAST);
    const packed = Buffer.from(t, 'base64url');
    packed[packed.length - 1] ^= 0xff; // flip last byte
    const tampered = packed.toString('base64url');
    await assert.rejects(
      () => decryptWithPassphrase(tampered, 'pw', FAST),
      err => err instanceof CryptoError && err.code === ErrorCode.DECRYPT_FAILED,
    );
  });

  it('rejects a truncated token', async () => {
    await assert.rejects(
      () => decryptWithPassphrase('AAAA', 'pw', FAST),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_CIPHERTEXT,
    );
  });

  it('rejects non-string token', async () => {
    await assert.rejects(
      () => decryptWithPassphrase(null, 'pw', FAST),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('rejects non-string, non-buffer data on encrypt', async () => {
    for (const bad of [null, undefined, 42, {}, []]) {
      await assert.rejects(
        () => encryptWithPassphrase(bad, 'pw', FAST),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });
});
