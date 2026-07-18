import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as nodeSign, verify as nodeVerify } from 'node:crypto';

import { derToRaw, rawToDer, EC_COORD_BYTES } from '../src/signing/ecdsa.js';

test('EC_COORD_BYTES: known curves', () => {
  assert.equal(EC_COORD_BYTES['P-256'], 32);
  assert.equal(EC_COORD_BYTES['P-384'], 48);
  assert.equal(EC_COORD_BYTES['P-521'], 66);
  assert.equal(EC_COORD_BYTES.secp256k1, 32);
});

for (const [curve, alg] of [
  ['P-256', 'sha256'],
  ['P-384', 'sha384'],
]) {
  test(`round-trip: DER → raw → DER produces a verifiable signature (${curve})`, () => {
    const namedCurve = curve === 'P-256' ? 'prime256v1' : 'secp384r1';
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve });
    const message = Buffer.from('hello ecdsa');

    const der = nodeSign(alg, message, privateKey);
    const raw = derToRaw(der, curve);
    assert.equal(raw.length, EC_COORD_BYTES[curve] * 2);

    const derBack = rawToDer(raw, curve);
    assert.equal(nodeVerify(alg, message, publicKey, derBack), true);
  });
}

test('derToRaw: unknown curve throws', () => {
  assert.throws(() => derToRaw(Buffer.alloc(10), 'BOGUS'), /unknown curve/);
});

test('derToRaw: rejects truncated DER', () => {
  assert.throws(() => derToRaw(Buffer.alloc(4), 'P-256'), /truncated/);
});

test('derToRaw: rejects non-SEQUENCE header', () => {
  const bogus = Buffer.from([0x31, 0x0e, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0, 0, 0, 0]);
  assert.throws(() => derToRaw(bogus, 'P-256'), /SEQUENCE/);
});

test('rawToDer: rejects wrong length', () => {
  assert.throws(() => rawToDer(Buffer.alloc(63), 'P-256'), /expected 64 bytes/);
});
