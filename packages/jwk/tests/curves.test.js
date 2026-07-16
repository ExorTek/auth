import { test } from 'node:test';
import assert from 'node:assert/strict';

import { generate } from '../src/generate.js';
import { importJWK } from '../src/import.js';
import { exportJWK } from '../src/export.js';
import { thumbprint } from '../src/index.js';
import { validate } from '../src/validate.js';
import { EC_COORD_BYTES, OKP_KEY_BYTES } from '../src/internal/curves.js';
import { decode as b64uDecode } from '../src/internal/base64url.js';

const EC_CURVES = ['P-256', 'P-384', 'P-521', 'secp256k1'];
const OKP_SIGNING = ['Ed25519', 'Ed448'];
const OKP_KEX = ['X25519', 'X448'];

for (const curve of EC_CURVES) {
  test(`EC ${curve}: generate → validate → import/export roundtrip`, async () => {
    const { publicJwk, privateJwk } = await generate('EC', { curve, kid: `ec-${curve}` });
    assert.equal(publicJwk.crv, curve);
    assert.equal(privateJwk.crv, curve);
    validate(publicJwk, { requirePublic: true });
    validate(privateJwk, { requirePrivate: true });

    // Coordinate lengths match the spec table.
    const size = EC_COORD_BYTES[curve];
    assert.equal(b64uDecode(publicJwk.x).length, size);
    assert.equal(b64uDecode(publicJwk.y).length, size);
    assert.equal(b64uDecode(privateJwk.d).length, size);

    const key = await importJWK(privateJwk);
    const back = await exportJWK(key);
    assert.equal(back.crv, curve);
    assert.equal(back.d, privateJwk.d);

    // Thumbprint is stable across import→export
    assert.equal(await thumbprint(back), await thumbprint(privateJwk));
  });
}

for (const curve of OKP_SIGNING) {
  test(`OKP ${curve}: generate → validate → import/export roundtrip`, async () => {
    const { publicJwk, privateJwk } = await generate('OKP', { curve, use: 'sig' });
    assert.equal(publicJwk.crv, curve);
    validate(publicJwk, { requirePublic: true });
    validate(privateJwk, { requirePrivate: true });

    const size = OKP_KEY_BYTES[curve];
    assert.equal(b64uDecode(publicJwk.x).length, size);
    assert.equal(b64uDecode(privateJwk.d).length, size);

    const key = await importJWK(privateJwk);
    const back = await exportJWK(key);
    assert.equal(back.crv, curve);
    assert.equal(back.d, privateJwk.d);
    assert.equal(await thumbprint(back), await thumbprint(privateJwk));
  });
}

for (const curve of OKP_KEX) {
  test(`OKP ${curve}: key-agreement generate + import roundtrip`, async () => {
    const { publicJwk, privateJwk } = await generate('OKP', { curve, use: 'enc' });
    assert.equal(publicJwk.crv, curve);
    assert.equal(publicJwk.use, 'enc');
    validate(publicJwk, { requirePublic: true });
    validate(privateJwk, { requirePrivate: true });

    const size = OKP_KEY_BYTES[curve];
    assert.equal(b64uDecode(publicJwk.x).length, size);

    const key = await importJWK(privateJwk);
    const back = await exportJWK(key);
    assert.equal(back.crv, curve);
    assert.equal(back.d, privateJwk.d);
  });
}

test('RSA 2048: generate → validate → import/export roundtrip', async () => {
  const { publicJwk, privateJwk } = await generate('RSA', { modulusLength: 2048 });
  validate(publicJwk, { requirePublic: true });
  validate(privateJwk, { requirePrivate: true });

  const key = await importJWK(privateJwk);
  const back = await exportJWK(key);
  assert.equal(back.n, privateJwk.n);
  assert.equal(back.e, privateJwk.e);
  assert.equal(back.d, privateJwk.d);
  assert.equal(await thumbprint(back), await thumbprint(privateJwk));
});

test('RSA 3072: generate + roundtrip', async () => {
  const { publicJwk, privateJwk } = await generate('RSA', { modulusLength: 3072 });
  validate(publicJwk, { requirePublic: true });
  validate(privateJwk, { requirePrivate: true });
  const key = await importJWK(publicJwk);
  const back = await exportJWK(key);
  assert.equal(back.n, publicJwk.n);
});

test('oct: various bit sizes produce k of matching length', async () => {
  for (const bits of [128, 192, 256, 384, 512]) {
    const { publicJwk } = await generate('oct', { bits });
    const bytes = b64uDecode(publicJwk.k);
    assert.equal(bytes.length, bits / 8, `oct bits=${bits}`);
  }
});

test('metadata roundtrip: kid / use / alg / key_ops survive import→export via decoration', async () => {
  const { privateJwk } = await generate('EC', {
    curve: 'P-256',
    kid: 'meta-1',
    use: 'sig',
    alg: 'ES256',
    key_ops: ['sign'],
  });
  assert.equal(privateJwk.kid, 'meta-1');
  assert.equal(privateJwk.use, 'sig');
  assert.equal(privateJwk.alg, 'ES256');
  assert.deepEqual(privateJwk.key_ops, ['sign']);

  const key = await importJWK(privateJwk);
  // node:crypto strips JWK decorators on export; verify our decorator
  // pass-through restores them when the caller supplies them.
  const back = await exportJWK(key, {
    kid: privateJwk.kid,
    use: privateJwk.use,
    alg: privateJwk.alg,
    key_ops: privateJwk.key_ops,
  });
  assert.equal(back.kid, 'meta-1');
  assert.equal(back.use, 'sig');
  assert.equal(back.alg, 'ES256');
  assert.deepEqual(back.key_ops, ['sign']);
});
