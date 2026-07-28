import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { base64url } from '@exortek/crypto/encode';
import { importCoseKey, algorithmForId, ALGORITHMS, DEFAULT_SUPPORTED_ALGORITHMS } from '../../src/cose/key.js';

/**
 * Build a COSE Key Map (Map<int, ...>) from a JWK. Mirrors what our
 * CBOR decoder would produce from a real WebAuthn credential public
 * key: integer labels, negative-int parameters, byte-string
 * coordinates.
 */
function jwkToCoseMap(jwk, alg) {
  const m = new Map();
  m.set(3, alg); // alg label
  if (jwk.kty === 'EC') {
    m.set(1, 2); // kty=EC2
    const crvId = jwk.crv === 'P-256' ? 1 : jwk.crv === 'P-384' ? 2 : 3;
    m.set(-1, crvId);
    m.set(-2, base64url.decode(jwk.x));
    m.set(-3, base64url.decode(jwk.y));
  } else if (jwk.kty === 'OKP') {
    m.set(1, 1); // kty=OKP
    m.set(-1, 6); // Ed25519
    m.set(-2, base64url.decode(jwk.x));
  } else if (jwk.kty === 'RSA') {
    m.set(1, 3); // kty=RSA
    m.set(-1, base64url.decode(jwk.n));
    m.set(-2, base64url.decode(jwk.e));
  } else {
    throw new Error(`fixture: unsupported kty ${jwk.kty}`);
  }
  return m;
}

describe('COSE — importCoseKey (EC)', () => {
  for (const [alg, curve] of [
    [-7, 'P-256'],
    [-35, 'P-384'],
    [-36, 'P-521'],
  ]) {
    test(`imports and verifies ${ALGORITHMS[alg].name} round-trip`, () => {
      const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: curve });
      const jwk = publicKey.export({ format: 'jwk' });
      const cose = jwkToCoseMap(jwk, alg);

      const imported = importCoseKey(cose);
      assert.equal(imported.algorithm, alg);
      assert.equal(imported.name, ALGORITHMS[alg].name);
      assert.equal(imported.jwk.crv, curve);

      // Real sign / verify — proves the KeyObject is usable end-to-end.
      const data = new TextEncoder().encode('hello passkey');
      const sig = sign(ALGORITHMS[alg].nodeAlgorithm, data, {
        key: privateKey,
        dsaEncoding: 'der',
      });
      const ok = verify(ALGORITHMS[alg].nodeAlgorithm, data, { key: imported.publicKey, dsaEncoding: 'der' }, sig);
      assert.equal(ok, true);
    });
  }

  test('rejects EC2 without x/y', () => {
    const m = new Map([
      [1, 2],
      [3, -7],
      [-1, 1],
    ]);
    assert.throws(() => importCoseKey(m), /x and y must be byte strings/);
  });

  test('rejects EC2 with wrong-length coordinates', () => {
    const m = new Map([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, new Uint8Array(16)],
      [-3, new Uint8Array(16)],
    ]);
    assert.throws(() => importCoseKey(m), /P-256 coordinates must be 32 bytes/);
  });

  test('rejects EC2 with curve/alg mismatch (ES256 declared, P-384 supplied)', () => {
    const m = new Map([
      [1, 2],
      [3, -7],
      [-1, 2], // P-384
      [-2, new Uint8Array(48)],
      [-3, new Uint8Array(48)],
    ]);
    assert.throws(() => importCoseKey(m), /does not match algorithm ES256/);
  });

  test('rejects unknown EC curve id', () => {
    const m = new Map([
      [1, 2],
      [3, -7],
      [-1, 99],
      [-2, new Uint8Array(32)],
      [-3, new Uint8Array(32)],
    ]);
    assert.throws(() => importCoseKey(m), /unsupported curve/);
  });
});

describe('COSE — importCoseKey (OKP / Ed25519)', () => {
  test('imports and verifies EdDSA round-trip', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const jwk = publicKey.export({ format: 'jwk' });
    const cose = jwkToCoseMap(jwk, -8);

    const imported = importCoseKey(cose);
    assert.equal(imported.algorithm, -8);
    assert.equal(imported.name, 'EdDSA');
    assert.equal(imported.jwk.crv, 'Ed25519');

    const data = new TextEncoder().encode('hello passkey');
    const sig = sign(null, data, privateKey);
    const ok = verify(null, data, imported.publicKey, sig);
    assert.equal(ok, true);
  });

  test('rejects OKP with wrong-length x', () => {
    const m = new Map([
      [1, 1],
      [3, -8],
      [-1, 6],
      [-2, new Uint8Array(16)],
    ]);
    assert.throws(() => importCoseKey(m), /Ed25519 public key must be 32 bytes/);
  });

  test('rejects OKP X25519 (not a signature curve)', () => {
    const m = new Map([
      [1, 1],
      [3, -8],
      [-1, 4], // X25519 — encryption/agreement, not signing
      [-2, new Uint8Array(32)],
    ]);
    assert.throws(() => importCoseKey(m), /not a signature curve/);
  });
});

describe('COSE — importCoseKey (RSA)', () => {
  for (const [alg, hash] of [
    [-257, 'SHA256'],
    [-258, 'SHA384'],
    [-259, 'SHA512'],
  ]) {
    test(`imports and verifies ${ALGORITHMS[alg].name} (PKCS#1 v1.5) round-trip`, () => {
      const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
      const jwk = publicKey.export({ format: 'jwk' });
      const cose = jwkToCoseMap(jwk, alg);

      const imported = importCoseKey(cose);
      assert.equal(imported.algorithm, alg);
      assert.equal(imported.name, ALGORITHMS[alg].name);

      const data = new TextEncoder().encode('hello passkey');
      const sig = sign(`RSA-${hash}`, data, privateKey);
      const ok = verify(`RSA-${hash}`, data, imported.publicKey, sig);
      assert.equal(ok, true);
    });
  }

  for (const [alg, hash, saltLen] of [
    [-37, 'SHA256', 32],
    [-38, 'SHA384', 48],
    [-39, 'SHA512', 64],
  ]) {
    test(`imports and verifies ${ALGORITHMS[alg].name} (PSS) round-trip`, () => {
      // Use a plain RSA key + PSS padding at sign/verify time — that's
      // what real authenticators produce (the key is a normal RSA key,
      // the algorithm choice adds the padding scheme).
      const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
      const jwk = publicKey.export({ format: 'jwk' });
      const cose = jwkToCoseMap(jwk, alg);

      const imported = importCoseKey(cose);
      assert.equal(imported.name, ALGORITHMS[alg].name);

      const data = new TextEncoder().encode('hello passkey');
      const sig = sign(hash, data, { key: privateKey, padding: 6, saltLength: saltLen });
      const ok = verify(hash, data, { key: imported.publicKey, padding: 6, saltLength: saltLen }, sig);
      assert.equal(ok, true);
    });
  }

  test('rejects RSA with missing exponent', () => {
    const m = new Map([
      [1, 3],
      [3, -257],
      [-1, new Uint8Array(256)],
    ]);
    assert.throws(() => importCoseKey(m), /n and e must be byte strings/);
  });

  test('rejects RSA modulus below 2048 bits', () => {
    // 1024-bit key — historically legal per JWK but a downgrade for FIDO2.
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
    const jwk = publicKey.export({ format: 'jwk' });
    const cose = jwkToCoseMap(jwk, -257);
    assert.throws(() => importCoseKey(cose), /1024 bits, minimum 2048/);
  });
});

describe('COSE — argument shape guards', () => {
  test('rejects non-Map input', () => {
    assert.throws(() => importCoseKey({}), /expected a Map/);
  });

  test('rejects missing alg', () => {
    const m = new Map([[1, 2]]);
    assert.throws(() => importCoseKey(m), /missing or non-integer alg/);
  });

  test('rejects unsupported alg', () => {
    const m = new Map([
      [1, 2],
      [3, -65535],
    ]);
    assert.throws(() => importCoseKey(m), /unsupported algorithm/);
  });

  test('rejects unknown kty', () => {
    const m = new Map([
      [1, 99],
      [3, -7],
    ]);
    assert.throws(() => importCoseKey(m), /unsupported kty/);
  });
});

describe('COSE — algorithmForId + default supported set', () => {
  test('every supported id resolves', () => {
    for (const idStr of Object.keys(ALGORITHMS)) {
      const params = algorithmForId(Number(idStr));
      assert.equal(typeof params.name, 'string');
    }
  });

  test('unknown id throws', () => {
    assert.throws(() => algorithmForId(999), /unsupported algorithm/);
  });

  test('DEFAULT_SUPPORTED_ALGORITHMS covers EdDSA, ES256, RS256', () => {
    assert.deepEqual(DEFAULT_SUPPORTED_ALGORITHMS, [-8, -7, -257]);
    for (const alg of DEFAULT_SUPPORTED_ALGORITHMS) {
      assert.ok(algorithmForId(alg));
    }
  });
});
