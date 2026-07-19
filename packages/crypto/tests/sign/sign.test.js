import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { generateSignKeyPair, sign, verify } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

const ALGOS = ['rs256', 'ps256', 'ps384', 'ps512', 'es256', 'es384', 'es512', 'eddsa'];

describe('sign / verify — every algorithm round-trips', () => {
  for (const algo of ALGOS) {
    it(`${algo} round-trips`, async () => {
      const { publicKey, privateKey } = await generateSignKeyPair(algo);
      const sig = sign('payload', privateKey, { algo });
      assert.ok(Buffer.isBuffer(sig));
      assert.equal(verify('payload', sig, publicKey, { algo }), true);
    });
  }
});

describe('sign / verify — negative cases', () => {
  it('verify returns false for a wrong key', async () => {
    const kp = await generateSignKeyPair('es256');
    const other = await generateSignKeyPair('es256');
    const sig = sign('hello', kp.privateKey, { algo: 'es256' });
    assert.equal(verify('hello', sig, other.publicKey, { algo: 'es256' }), false);
  });

  it('verify returns false for tampered data', async () => {
    const kp = await generateSignKeyPair('ps256');
    const sig = sign('hello', kp.privateKey, { algo: 'ps256' });
    assert.equal(verify('goodbye', sig, kp.publicKey, { algo: 'ps256' }), false);
  });

  it('verify returns false for a tampered signature', async () => {
    const kp = await generateSignKeyPair('es256');
    const sig = sign('hello', kp.privateKey, { algo: 'es256' });
    sig[0] ^= 0xff;
    assert.equal(verify('hello', sig, kp.publicKey, { algo: 'es256' }), false);
  });

  it('verify returns false when the algorithm changes at verify time', async () => {
    const kp256 = await generateSignKeyPair('es256');
    const sig = sign('hello', kp256.privateKey, { algo: 'es256' });
    // ES384 verify with an ES256 signature must reject (curve mismatch).
    const kp384 = await generateSignKeyPair('es384');
    assert.equal(verify('hello', sig, kp384.publicKey, { algo: 'es384' }), false);
  });
});

describe('sign / verify — options', () => {
  it('sign honors encoding option', async () => {
    const kp = await generateSignKeyPair('es256');
    const buf = sign('x', kp.privateKey, { algo: 'es256' });
    const hex = sign('x', kp.privateKey, { algo: 'es256', encoding: 'hex' });
    const b64u = sign('x', kp.privateKey, { algo: 'es256', encoding: 'base64url' });
    assert.equal(typeof hex, 'string');
    assert.equal(typeof b64u, 'string');
    // Signatures are non-deterministic (ECDSA/PS use randomness) — just check
    // types and that each round-trips independently:
    assert.equal(verify('x', buf, kp.publicKey, { algo: 'es256' }), true);
    assert.equal(verify('x', hex, kp.publicKey, { algo: 'es256', encoding: 'hex' }), true);
    assert.equal(verify('x', b64u, kp.publicKey, { algo: 'es256', encoding: 'base64url' }), true);
  });

  it('sign is deterministic for rs* / eddsa (no random component)', async () => {
    const rsa = await generateSignKeyPair('rs256');
    const eddsa = await generateSignKeyPair('eddsa');
    assert.deepEqual(sign('same', rsa.privateKey, { algo: 'rs256' }), sign('same', rsa.privateKey, { algo: 'rs256' }));
    assert.deepEqual(
      sign('same', eddsa.privateKey, { algo: 'eddsa' }),
      sign('same', eddsa.privateKey, { algo: 'eddsa' }),
    );
  });
});

describe('sign / verify — argument validation', () => {
  it('sign rejects unsupported algorithm', async () => {
    const kp = await generateSignKeyPair('es256');
    assert.throws(
      () => sign('x', kp.privateKey, { algo: 'hs256' }),
      err => err instanceof CryptoError && err.code === ErrorCode.UNSUPPORTED_ALGORITHM,
    );
  });

  it('sign rejects missing options.algo', async () => {
    const kp = await generateSignKeyPair('es256');
    assert.throws(
      () => sign('x', kp.privateKey, {}),
      err => err instanceof CryptoError && err.code === ErrorCode.UNSUPPORTED_ALGORITHM,
    );
  });

  it('sign rejects public key input', async () => {
    const kp = await generateSignKeyPair('es256');
    assert.throws(
      () => sign('x', kp.publicKey, { algo: 'es256' }),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_KEY,
    );
  });

  it('verify rejects private key input', async () => {
    const kp = await generateSignKeyPair('es256');
    const sig = sign('x', kp.privateKey, { algo: 'es256' });
    assert.throws(
      () => verify('x', sig, kp.privateKey, { algo: 'es256' }),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_KEY,
    );
  });

  it('sign rejects non-string, non-buffer data', async () => {
    const kp = await generateSignKeyPair('es256');
    for (const bad of [null, undefined, 42, {}, []]) {
      assert.throws(
        () => sign(bad, kp.privateKey, { algo: 'es256' }),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  it('verify rejects non-string, non-buffer signature', async () => {
    const kp = await generateSignKeyPair('es256');
    for (const bad of [null, undefined, 42, {}, []]) {
      assert.throws(
        () => verify('x', bad, kp.publicKey, { algo: 'es256' }),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });
});
