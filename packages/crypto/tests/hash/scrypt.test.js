import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { scrypt } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

// Small N/r/p to keep tests fast; production uses defaults.
const FAST = { N: 1024, r: 8, p: 1 };
const salt = Buffer.from('0123456789abcdef', 'utf8');

describe('scrypt', () => {
  it('returns a Buffer of the requested length by default', async () => {
    const key = await scrypt('passphrase', { salt, ...FAST });
    assert.ok(Buffer.isBuffer(key));
    assert.equal(key.length, 32);
  });

  it('is deterministic under the same (password, salt, N, r, p, keyLength)', async () => {
    const opts = { salt, keyLength: 32, ...FAST };
    const a = await scrypt('pass', opts);
    const b = await scrypt('pass', opts);
    assert.deepEqual(a, b);
  });

  it('produces different keys for different salts', async () => {
    const a = await scrypt('pass', { salt: Buffer.from('a'.repeat(16)), ...FAST });
    const b = await scrypt('pass', { salt: Buffer.from('b'.repeat(16)), ...FAST });
    assert.notDeepEqual(a, b);
  });

  it('produces different keys for different passwords', async () => {
    const a = await scrypt('pass-a', { salt, ...FAST });
    const b = await scrypt('pass-b', { salt, ...FAST });
    assert.notDeepEqual(a, b);
  });

  it('honors keyLength option', async () => {
    for (const keyLength of [16, 32, 64, 128]) {
      const key = await scrypt('pass', { salt, keyLength, ...FAST });
      assert.equal(key.length, keyLength);
    }
  });

  it('honors encoding option', async () => {
    const buf = await scrypt('pass', { salt, encoding: 'buffer', ...FAST });
    const hex = await scrypt('pass', { salt, encoding: 'hex', ...FAST });
    const b64u = await scrypt('pass', { salt, encoding: 'base64url', ...FAST });
    assert.deepEqual(Buffer.from(hex, 'hex'), buf);
    assert.deepEqual(Buffer.from(b64u, 'base64url'), buf);
  });

  it('accepts string or Buffer for both password and salt', async () => {
    const a = await scrypt('pass', { salt: 'saltysalt', ...FAST });
    const b = await scrypt(Buffer.from('pass'), { salt: Buffer.from('saltysalt'), ...FAST });
    assert.deepEqual(a, b);
  });

  it('requires salt', async () => {
    await assert.rejects(
      () => scrypt('pass'),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
    await assert.rejects(
      () => scrypt('pass', {}),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('rejects non-positive keyLength / N / r / p', async () => {
    await assert.rejects(
      () => scrypt('pass', { salt, keyLength: 0 }),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
    await assert.rejects(
      () => scrypt('pass', { salt, N: 0 }),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
    await assert.rejects(
      () => scrypt('pass', { salt, r: -1 }),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
    await assert.rejects(
      () => scrypt('pass', { salt, p: 1.5 }),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('respects maxmem override for larger N', async () => {
    // At N=2^15, memory demand exceeds Node's default 32 MiB in some tunings;
    // pass explicit maxmem to prove the parameter is wired through.
    const key = await scrypt('pass', {
      salt,
      N: 2 ** 14,
      r: 8,
      p: 1,
      maxmem: 128 * 1024 * 1024,
      keyLength: 32,
    });
    assert.equal(key.length, 32);
  });
});
