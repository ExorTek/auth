import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { thumbprint, generateSignKeyPair } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('thumbprint', () => {
  it('is deterministic for the same public key', async () => {
    const kp = await generateSignKeyPair('es256');
    assert.equal(thumbprint(kp.publicKey), thumbprint(kp.publicKey));
  });

  it('differs for different keys', async () => {
    const a = await generateSignKeyPair('es256');
    const b = await generateSignKeyPair('es256');
    assert.notEqual(thumbprint(a.publicKey), thumbprint(b.publicKey));
  });

  it('produces the same fingerprint for the private key as its public pair', async () => {
    const kp = await generateSignKeyPair('es256');
    assert.equal(thumbprint(kp.publicKey), thumbprint(kp.privateKey));
  });

  it('base64url output by default (JWT `kid` friendly)', async () => {
    const kp = await generateSignKeyPair('es256');
    assert.match(thumbprint(kp.publicKey), /^[A-Za-z0-9_-]+$/);
  });

  it('honors encoding option', async () => {
    const kp = await generateSignKeyPair('es256');
    const buf = thumbprint(kp.publicKey, { encoding: 'buffer' });
    assert.ok(Buffer.isBuffer(buf));
    assert.equal(buf.length, 32); // SHA-256
    assert.equal(thumbprint(kp.publicKey, { encoding: 'hex' }), buf.toString('hex'));
  });

  it('honors hash option', async () => {
    const kp = await generateSignKeyPair('es256');
    assert.equal(thumbprint(kp.publicKey, { hash: 'sha384', encoding: 'buffer' }).length, 48);
    assert.equal(thumbprint(kp.publicKey, { hash: 'sha512', encoding: 'buffer' }).length, 64);
  });

  it('works across all key types', async () => {
    for (const algo of ['rs256', 'es256', 'es384', 'es512', 'eddsa']) {
      const kp = await generateSignKeyPair(algo);
      assert.equal(typeof thumbprint(kp.publicKey), 'string');
    }
  });

  it('rejects non-KeyObject input', () => {
    for (const bad of [null, undefined, 'x', 42, {}, []]) {
      assert.throws(
        () => thumbprint(bad),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_KEY,
      );
    }
  });

  it('rejects unsupported hash', async () => {
    const kp = await generateSignKeyPair('es256');
    assert.throws(
      () => thumbprint(kp.publicKey, { hash: 'md5' }),
      err => err instanceof CryptoError && err.code === ErrorCode.UNSUPPORTED_ALGORITHM,
    );
  });
});
