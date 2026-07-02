import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { cipher, KEY_AGREEMENT_ALGOS } from '../../src/cipher/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('cipher.deriveSharedSecret', () => {
  it('X25519 — Alice and Bob derive the same 32-byte key', async () => {
    const alice = await cipher.generateKeyPair('x25519');
    const bob = await cipher.generateKeyPair('x25519');
    const sA = cipher.deriveSharedSecret(alice.privateKey, bob.publicKey);
    const sB = cipher.deriveSharedSecret(bob.privateKey, alice.publicKey);
    assert.equal(sA.length, 32);
    assert.deepEqual(sA, sB);
  });

  it('ECDH-P256 — parties agree on the same secret', async () => {
    const alice = await cipher.generateKeyPair('ecdh-p256');
    const bob = await cipher.generateKeyPair('ecdh-p256');
    const sA = cipher.deriveSharedSecret(alice.privateKey, bob.publicKey);
    const sB = cipher.deriveSharedSecret(bob.privateKey, alice.publicKey);
    assert.deepEqual(sA, sB);
  });

  it('ECDH-P384 — parties agree on the same secret', async () => {
    const alice = await cipher.generateKeyPair('ecdh-p384');
    const bob = await cipher.generateKeyPair('ecdh-p384');
    const sA = cipher.deriveSharedSecret(alice.privateKey, bob.publicKey);
    const sB = cipher.deriveSharedSecret(bob.privateKey, alice.publicKey);
    assert.deepEqual(sA, sB);
  });

  it('different key pairs derive different secrets', async () => {
    const a1 = await cipher.generateKeyPair('x25519');
    const a2 = await cipher.generateKeyPair('x25519');
    const b = await cipher.generateKeyPair('x25519');
    const s1 = cipher.deriveSharedSecret(a1.privateKey, b.publicKey);
    const s2 = cipher.deriveSharedSecret(a2.privateKey, b.publicKey);
    assert.notDeepEqual(s1, s2);
  });

  it('length option controls the output size', async () => {
    const a = await cipher.generateKeyPair('x25519');
    const b = await cipher.generateKeyPair('x25519');
    for (const length of [16, 32, 48, 64]) {
      const s = cipher.deriveSharedSecret(a.privateKey, b.publicKey, { length });
      assert.equal(s.length, length);
    }
  });

  it('info + salt materially change the derived key (HKDF domain separation)', async () => {
    const a = await cipher.generateKeyPair('x25519');
    const b = await cipher.generateKeyPair('x25519');
    const s1 = cipher.deriveSharedSecret(a.privateKey, b.publicKey, { info: 'session' });
    const s2 = cipher.deriveSharedSecret(a.privateKey, b.publicKey, { info: 'refresh' });
    assert.notDeepEqual(s1, s2);
  });

  it('rejects mismatched curves', async () => {
    const a = await cipher.generateKeyPair('ecdh-p256');
    const b = await cipher.generateKeyPair('x25519');
    assert.throws(
      () => cipher.deriveSharedSecret(a.privateKey, b.publicKey),
      (err) => err instanceof CryptoError && err.code === ErrorCode.INVALID_KEY,
    );
  });

  it('rejects invalid keys', async () => {
    const a = await cipher.generateKeyPair('x25519');
    assert.throws(
      () => cipher.deriveSharedSecret(a.publicKey, a.publicKey), // both public
      (err) => err instanceof CryptoError && err.code === ErrorCode.INVALID_KEY,
    );
  });

  it('KEY_AGREEMENT_ALGOS lists every supported curve', () => {
    assert.deepEqual([...KEY_AGREEMENT_ALGOS].sort(), ['ecdh-p256', 'ecdh-p384', 'x25519']);
  });
});
