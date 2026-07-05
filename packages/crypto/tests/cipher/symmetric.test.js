import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

import {
  cipher,
  encryptSymmetric,
  decryptSymmetric,
  SYMMETRIC_ALGOS,
} from '../../src/cipher/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('cipher symmetric (AES-256-GCM default)', () => {
  let key;
  before(async () => {
    key = await cipher.generateKey();
  });

  it('generateKey returns a secret KeyObject', () => {
    assert.equal(key.type, 'secret');
    assert.equal(key.symmetricKeySize, 32); // 256 bits
  });

  it('encrypt returns { ciphertext, iv, tag } buffers of expected sizes', () => {
    const { ciphertext, iv, tag } = cipher.encrypt('hello', key);
    assert.ok(Buffer.isBuffer(ciphertext));
    assert.equal(iv.length, 12); // GCM nonce
    assert.equal(tag.length, 16); // GCM auth tag
    assert.equal(ciphertext.length, 5); // 'hello' bytes
  });

  it('round-trips arbitrary UTF-8', () => {
    const plaintext = 'café ☕ — 你好';
    const { ciphertext, iv, tag } = cipher.encrypt(plaintext, key);
    assert.equal(cipher.decrypt(ciphertext, key, { iv, tag }).toString('utf8'), plaintext);
  });

  it('encrypts Buffer input directly', () => {
    const src = Buffer.from([1, 2, 3, 4, 5]);
    const { ciphertext, iv, tag } = cipher.encrypt(src, key);
    assert.deepEqual(cipher.decrypt(ciphertext, key, { iv, tag }), src);
  });

  it('produces different ciphertexts for the same plaintext (fresh IV)', () => {
    const a = cipher.encrypt('same', key);
    const b = cipher.encrypt('same', key);
    assert.notDeepEqual(a.iv, b.iv);
    assert.notDeepEqual(a.ciphertext, b.ciphertext);
  });

  it('rejects tampered ciphertext (auth tag mismatch)', () => {
    const { ciphertext, iv, tag } = cipher.encrypt('secret', key);
    ciphertext[0] ^= 0xff;
    assert.throws(
      () => cipher.decrypt(ciphertext, key, { iv, tag }),
      (err) => err instanceof CryptoError && err.code === ErrorCode.DECRYPT_FAILED,
    );
  });

  it('rejects wrong key', async () => {
    const { ciphertext, iv, tag } = cipher.encrypt('secret', key);
    const wrong = await cipher.generateKey();
    assert.throws(
      () => cipher.decrypt(ciphertext, wrong, { iv, tag }),
      (err) => err instanceof CryptoError && err.code === ErrorCode.DECRYPT_FAILED,
    );
  });

  it('supports AAD (additional authenticated data)', () => {
    const aad = 'user:42';
    const { ciphertext, iv, tag } = cipher.encrypt('secret', key, { aad });
    // Correct AAD decrypts.
    assert.equal(cipher.decrypt(ciphertext, key, { iv, tag, aad }).toString('utf8'), 'secret');
    // Wrong AAD fails.
    assert.throws(
      () => cipher.decrypt(ciphertext, key, { iv, tag, aad: 'user:99' }),
      (err) => err instanceof CryptoError && err.code === ErrorCode.DECRYPT_FAILED,
    );
  });

  it('rejects non-secret key on encrypt', async () => {
    const kp = await cipher.generateKeyPair('x25519');
    assert.throws(
      () => cipher.encrypt('x', kp.privateKey),
      (err) => err instanceof CryptoError && err.code === ErrorCode.INVALID_KEY,
    );
  });
});

describe('cipher explicit named exports', () => {
  it('encryptSymmetric / decryptSymmetric round-trip (same as polymorphic path)', async () => {
    const key = await cipher.generateKey();
    const { ciphertext, iv, tag } = encryptSymmetric('hello', key);
    assert.equal(decryptSymmetric(ciphertext, key, { iv, tag }).toString('utf8'), 'hello');
  });

  it('SYMMETRIC_ALGOS lists all supported symmetric algorithms', () => {
    assert.deepEqual([...SYMMETRIC_ALGOS].sort(), [
      'aes-128-gcm',
      'aes-192-gcm',
      'aes-256-cbc',
      'aes-256-gcm',
      'chacha20-poly1305',
    ]);
  });

  it('aes-128-gcm round-trips (16-byte key)', async () => {
    const key = await cipher.generateKey('aes-128-gcm');
    assert.equal(key.symmetricKeySize, 16);
    const { ciphertext, iv, tag } = cipher.encrypt('hi', key, { algo: 'aes-128-gcm' });
    assert.equal(cipher.decrypt(ciphertext, key, { iv, tag, algo: 'aes-128-gcm' }).toString('utf8'), 'hi');
  });

  it('aes-192-gcm round-trips (24-byte key)', async () => {
    const key = await cipher.generateKey('aes-192-gcm');
    assert.equal(key.symmetricKeySize, 24);
    const { ciphertext, iv, tag } = cipher.encrypt('hi', key, { algo: 'aes-192-gcm' });
    assert.equal(cipher.decrypt(ciphertext, key, { iv, tag, algo: 'aes-192-gcm' }).toString('utf8'), 'hi');
  });
});

describe('cipher symmetric — algorithm variants', () => {
  it('supports chacha20-poly1305', async () => {
    const key = await cipher.generateKey('chacha20-poly1305');
    const { ciphertext, iv, tag } = cipher.encrypt('hello', key, { algo: 'chacha20-poly1305' });
    assert.equal(
      cipher.decrypt(ciphertext, key, { iv, tag, algo: 'chacha20-poly1305' }).toString('utf8'),
      'hello',
    );
  });

  it('supports aes-256-cbc (no auth tag)', async () => {
    const key = await cipher.generateKey('aes-256-cbc');
    const { ciphertext, iv, tag } = cipher.encrypt('hello', key, { algo: 'aes-256-cbc' });
    assert.equal(tag.length, 0);
    assert.equal(
      cipher.decrypt(ciphertext, key, { iv, algo: 'aes-256-cbc' }).toString('utf8'),
      'hello',
    );
  });

  it('rejects unsupported algorithm', async () => {
    const key = await cipher.generateKey();
    assert.throws(
      () => cipher.encrypt('x', key, { algo: 'aes-128-ecb' }),
      (err) => err instanceof CryptoError && err.code === ErrorCode.UNSUPPORTED_ALGORITHM,
    );
  });
});

describe('cipher encryptToString / decryptFromString', () => {
  let key;
  before(async () => {
    key = await cipher.generateKey();
  });

  it('round-trips through a single base64url token', () => {
    const token = cipher.encryptToString('user:123', key);
    assert.match(token, /^[A-Za-z0-9_-]+$/);
    assert.equal(cipher.decryptFromString(token, key).toString('utf8'), 'user:123');
  });

  it('rejects a truncated token', () => {
    const token = cipher.encryptToString('user:123', key);
    const short = token.slice(0, 10); // too short to contain iv+tag+ciphertext
    assert.throws(
      () => cipher.decryptFromString(short, key),
      (err) => err instanceof CryptoError && err.code === ErrorCode.INVALID_CIPHERTEXT,
    );
  });

  it('rejects a tampered token', () => {
    const token = cipher.encryptToString('user:123', key);
    // Flip a character to invalidate the packed data.
    const tampered = token.slice(0, -4) + 'AAAA';
    assert.throws(
      () => cipher.decryptFromString(tampered, key),
      (err) => err instanceof CryptoError && err.code === ErrorCode.DECRYPT_FAILED,
    );
  });
});
