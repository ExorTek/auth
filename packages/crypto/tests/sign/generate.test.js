import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { generateSignKeyPair, SIGN_ALGOS } from '../../src/sign/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('generateSignKeyPair', () => {
  it('returns a matching public/private pair for every supported algorithm', async () => {
    for (const algo of SIGN_ALGOS) {
      const kp = await generateSignKeyPair(algo);
      assert.equal(kp.publicKey.type, 'public', `algo=${algo}`);
      assert.equal(kp.privateKey.type, 'private', `algo=${algo}`);
    }
  });

  it('produces RSA keys of the correct modulus length for rs* and ps*', async () => {
    for (const algo of ['rs256', 'ps256', 'rs512', 'ps512']) {
      const kp = await generateSignKeyPair(algo);
      assert.equal(kp.publicKey.asymmetricKeyType, 'rsa');
      assert.equal(kp.publicKey.asymmetricKeyDetails.modulusLength, 2048);
    }
  });

  it('produces ECDSA keys on the expected curves', async () => {
    const curveByAlgo = { es256: 'prime256v1', es384: 'secp384r1', es512: 'secp521r1' };
    for (const [algo, curve] of Object.entries(curveByAlgo)) {
      const kp = await generateSignKeyPair(algo);
      assert.equal(kp.publicKey.asymmetricKeyType, 'ec');
      assert.equal(kp.publicKey.asymmetricKeyDetails.namedCurve, curve);
    }
  });

  it('produces Ed25519 keys for eddsa', async () => {
    const kp = await generateSignKeyPair('eddsa');
    assert.equal(kp.publicKey.asymmetricKeyType, 'ed25519');
  });

  it('rejects unsupported algorithms', async () => {
    await assert.rejects(
      () => generateSignKeyPair('unknown'),
      err => err instanceof CryptoError && err.code === ErrorCode.UNSUPPORTED_ALGORITHM,
    );
  });

  it('SIGN_ALGOS lists every JOSE-style algorithm', () => {
    assert.deepEqual([...SIGN_ALGOS].sort(), [
      'eddsa',
      'es256',
      'es384',
      'es512',
      'ps256',
      'ps384',
      'ps512',
      'rs256',
      'rs384',
      'rs512',
    ]);
  });
});
