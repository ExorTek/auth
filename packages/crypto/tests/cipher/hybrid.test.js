import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

import { cipher } from '../../src/cipher/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('cipher hybrid (RSA-wrapped AES)', () => {
  let publicKey;
  let privateKey;

  before(async () => {
    ({ publicKey, privateKey } = await cipher.generateKeyPair('rsa-oaep-256'));
  });

  it('envelope contains encryptedKey, iv, tag, ciphertext', () => {
    const env = cipher.encryptHybrid('data', publicKey);
    assert.ok(Buffer.isBuffer(env.encryptedKey));
    assert.equal(env.iv.length, 12);
    assert.equal(env.tag.length, 16);
    assert.ok(Buffer.isBuffer(env.ciphertext));
  });

  it('round-trips small payloads', () => {
    const env = cipher.encryptHybrid('hi', publicKey);
    assert.equal(cipher.decryptHybrid(env, privateKey).toString('utf8'), 'hi');
  });

  it('round-trips large payloads (larger than the RSA modulus)', () => {
    const big = Buffer.alloc(65_536).fill(0xab);
    const env = cipher.encryptHybrid(big, publicKey);
    assert.deepEqual(cipher.decryptHybrid(env, privateKey), big);
  });

  it('rejects a tampered ciphertext', () => {
    const env = cipher.encryptHybrid('secret', publicKey);
    env.ciphertext[0] ^= 0xff;
    assert.throws(
      () => cipher.decryptHybrid(env, privateKey),
      err => err instanceof CryptoError && err.code === ErrorCode.DECRYPT_FAILED,
    );
  });

  it('rejects a tampered wrapped key', () => {
    const env = cipher.encryptHybrid('secret', publicKey);
    env.encryptedKey[0] ^= 0xff;
    assert.throws(
      () => cipher.decryptHybrid(env, privateKey),
      err => err instanceof CryptoError && err.code === ErrorCode.DECRYPT_FAILED,
    );
  });

  it('rejects an envelope missing required fields', () => {
    assert.throws(
      () => cipher.decryptHybrid({ iv: Buffer.alloc(12), tag: Buffer.alloc(16) }, privateKey),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });
});
