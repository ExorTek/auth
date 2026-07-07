import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

import { cipher, encryptAsymmetric, decryptAsymmetric, ASYMMETRIC_ALGOS } from '../../src/cipher/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('cipher asymmetric (RSA-OAEP)', () => {
  let publicKey;
  let privateKey;

  before(async () => {
    ({ publicKey, privateKey } = await cipher.generateKeyPair('rsa-oaep-256'));
  });

  it('generateKeyPair returns a matching public/private RSA pair', () => {
    assert.equal(publicKey.type, 'public');
    assert.equal(privateKey.type, 'private');
    assert.equal(publicKey.asymmetricKeyType, 'rsa');
    assert.equal(privateKey.asymmetricKeyType, 'rsa');
  });

  it('round-trips small payloads', () => {
    const enc = cipher.encrypt('secret message', publicKey);
    assert.ok(Buffer.isBuffer(enc));
    assert.equal(cipher.decrypt(enc, privateKey).toString('utf8'), 'secret message');
  });

  it('produces non-deterministic ciphertext for the same plaintext', () => {
    const a = cipher.encrypt('same', publicKey);
    const b = cipher.encrypt('same', publicKey);
    assert.notDeepEqual(a, b); // OAEP includes fresh random padding
  });

  it('rejects wrong private key', async () => {
    const enc = cipher.encrypt('secret', publicKey);
    const other = await cipher.generateKeyPair('rsa-oaep-256');
    assert.throws(
      () => cipher.decrypt(enc, other.privateKey),
      err => err instanceof CryptoError && err.code === ErrorCode.DECRYPT_FAILED,
    );
  });

  it('supports rsa-oaep (SHA-1) as legacy option', async () => {
    const kp = await cipher.generateKeyPair('rsa-oaep');
    const enc = cipher.encrypt('legacy', kp.publicKey, { algo: 'rsa-oaep' });
    assert.equal(cipher.decrypt(enc, kp.privateKey, { algo: 'rsa-oaep' }).toString('utf8'), 'legacy');
  });

  it('encrypt rejects a private key input', () => {
    assert.throws(
      () => cipher.encrypt('x', privateKey),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_KEY,
    );
  });

  it('decrypt rejects a public key input', () => {
    const enc = cipher.encrypt('x', publicKey);
    assert.throws(
      () => cipher.decrypt(enc, publicKey),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_KEY,
    );
  });

  it('encryptAsymmetric / decryptAsymmetric round-trip via explicit named exports', () => {
    const enc = encryptAsymmetric('explicit', publicKey, { algo: 'rsa-oaep-256' });
    assert.equal(decryptAsymmetric(enc, privateKey, { algo: 'rsa-oaep-256' }).toString('utf8'), 'explicit');
  });

  it('ASYMMETRIC_ALGOS lists both RSA-OAEP variants', () => {
    assert.deepEqual([...ASYMMETRIC_ALGOS].sort(), ['rsa-oaep', 'rsa-oaep-256']);
  });
});
