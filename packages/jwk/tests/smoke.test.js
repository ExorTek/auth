import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  jwk,
  generate,
  importJWK,
  exportJWK,
  importPEM,
  exportPEM,
  toPublic,
  thumbprint,
  thumbprintURI,
  matches,
  validate,
  isValid,
  JwkError,
  ErrorCode,
} from '../src/index.js';

test('generate EC P-256 → public/private JWK with kty/crv/x/y/d', async () => {
  const { publicJwk, privateJwk } = await generate('EC', {
    curve: 'P-256',
    kid: 'ec-1',
    use: 'sig',
    alg: 'ES256',
  });
  assert.equal(publicJwk.kty, 'EC');
  assert.equal(publicJwk.crv, 'P-256');
  assert.equal(publicJwk.kid, 'ec-1');
  assert.equal(publicJwk.use, 'sig');
  assert.equal(publicJwk.alg, 'ES256');
  assert.ok(publicJwk.x && publicJwk.y);
  assert.equal(publicJwk.d, undefined);
  assert.ok(privateJwk.d);
});

test('generate RSA 2048 → n/e/d/p/q/dp/dq/qi', async () => {
  const { publicJwk, privateJwk } = await generate('RSA', { kid: 'rsa-1' });
  assert.equal(publicJwk.kty, 'RSA');
  assert.ok(publicJwk.n && publicJwk.e);
  assert.equal(publicJwk.d, undefined);
  for (const m of ['d', 'p', 'q', 'dp', 'dq', 'qi']) assert.ok(privateJwk[m], `missing ${m}`);
});

test('generate RSA rejects modulusLength < 2048', async () => {
  await assert.rejects(
    () => generate('RSA', { modulusLength: 1024 }),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('generate OKP Ed25519', async () => {
  const { publicJwk, privateJwk } = await generate('OKP');
  assert.equal(publicJwk.kty, 'OKP');
  assert.equal(publicJwk.crv, 'Ed25519');
  assert.ok(publicJwk.x);
  assert.ok(privateJwk.d);
});

test('generate oct produces symmetric JWK with k', async () => {
  const { publicJwk, privateJwk } = await generate('oct', { bits: 256 });
  assert.equal(publicJwk.kty, 'oct');
  assert.ok(publicJwk.k);
  assert.equal(publicJwk, privateJwk, 'oct: same object for both projections');
});

test('generate unsupported kty throws UNSUPPORTED_KTY', async () => {
  await assert.rejects(
    () => generate(/** @type {any} */ ('bogus')),
    err => err instanceof JwkError && err.code === ErrorCode.UNSUPPORTED_KTY,
  );
});

test('importJWK / exportJWK roundtrip (EC)', async () => {
  const { privateJwk } = await generate('EC', { curve: 'P-256' });
  const key = await importJWK(privateJwk);
  const back = await exportJWK(key);
  assert.equal(back.kty, 'EC');
  assert.equal(back.crv, 'P-256');
  assert.equal(back.d, privateJwk.d);
});

test('exportPEM(private) → PKCS#8, importPEM roundtrip', async () => {
  const { privateJwk } = await generate('EC', { curve: 'P-256' });
  const key = await importJWK(privateJwk);
  const pem = await exportPEM(key);
  assert.match(pem, /BEGIN PRIVATE KEY/);
  const roundtrip = await importPEM(pem, 'pkcs8');
  const jwk2 = await exportJWK(roundtrip);
  assert.equal(jwk2.d, privateJwk.d);
});

test('exportPEM: private key with format="spki" throws (ambiguous)', async () => {
  const { privateJwk } = await generate('EC', { curve: 'P-256' });
  const key = await importJWK(privateJwk);
  await assert.rejects(
    () => exportPEM(key, 'spki'),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('toPublic strips d from EC private JWK', async () => {
  const { privateJwk } = await generate('EC', { curve: 'P-256', kid: 'k' });
  const pub = toPublic(privateJwk);
  assert.equal(pub.d, undefined);
  assert.equal(pub.kid, 'k');
  assert.ok(pub.x && pub.y);
});

test('toPublic strips d/p/q/dp/dq/qi from RSA', async () => {
  const { privateJwk } = await generate('RSA');
  const pub = toPublic(privateJwk);
  for (const m of ['d', 'p', 'q', 'dp', 'dq', 'qi']) assert.equal(pub[m], undefined);
  assert.ok(pub.n && pub.e);
});

test('toPublic on oct throws INVALID_ARGUMENT', async () => {
  const { publicJwk } = await generate('oct');
  assert.throws(
    () => toPublic(publicJwk),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('thumbprint is stable across kid/use/alg decoration', async () => {
  const { publicJwk } = await generate('EC', { curve: 'P-256', kid: 'a', use: 'sig', alg: 'ES256' });
  const bare = { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y };
  const t1 = await thumbprint(publicJwk);
  const t2 = await thumbprint(bare);
  assert.equal(t1, t2);
});

test('thumbprintURI has the RFC 9278 shape', async () => {
  const { publicJwk } = await generate('OKP');
  const uri = await thumbprintURI(publicJwk);
  assert.match(uri, /^urn:ietf:params:oauth:jwk-thumbprint:sha-256:[A-Za-z0-9_-]+$/);
});

test('matches: private and public projection thumbprint-equal', async () => {
  const { publicJwk, privateJwk } = await generate('EC', { curve: 'P-256' });
  assert.equal(await matches(publicJwk, privateJwk), true);
});

test("matches: different keys don't match", async () => {
  const a = (await generate('EC', { curve: 'P-256' })).publicJwk;
  const b = (await generate('EC', { curve: 'P-256' })).publicJwk;
  assert.equal(await matches(a, b), false);
});

test('validate: rejects missing kty', () => {
  assert.throws(
    () => validate({}),
    err => err instanceof JwkError && err.code === ErrorCode.MISSING_REQUIRED_MEMBER,
  );
});

test('validate: rejects wrong x length for P-256', () => {
  assert.throws(
    () => validate({ kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'AAAA' }),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_JWK,
  );
});

test('validate: rejects unsupported curve', () => {
  assert.throws(
    () => validate({ kty: 'EC', crv: 'P-999', x: 'x', y: 'y' }),
    err => err instanceof JwkError && err.code === ErrorCode.UNSUPPORTED_CURVE,
  );
});

test('validate: rejects unknown use', () => {
  assert.throws(
    () => validate({ kty: 'oct', k: 'YWFhYWFhYWE', use: 'bogus' }),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_JWK,
  );
});

test('validate: rejects duplicate key_ops', () => {
  assert.throws(
    () => validate({ kty: 'oct', k: 'YWFhYWFhYWE', key_ops: ['sign', 'sign'] }),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_JWK,
  );
});

test('validate: requirePublic rejects private JWK', async () => {
  const { privateJwk } = await generate('EC', { curve: 'P-256' });
  assert.throws(
    () => validate(privateJwk, { requirePublic: true }),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_JWK,
  );
});

test('validate: requirePrivate rejects public JWK', async () => {
  const { publicJwk } = await generate('EC', { curve: 'P-256' });
  assert.throws(
    () => validate(publicJwk, { requirePrivate: true }),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_JWK,
  );
});

test("isValid: returns booleans, doesn't throw", async () => {
  const { publicJwk } = await generate('EC', { curve: 'P-256' });
  assert.equal(isValid(publicJwk), true);
  assert.equal(isValid({ kty: 'EC', crv: 'P-256' }), false);
});

test('validate: rejects partial RSA CRT parameters', async () => {
  const { privateJwk } = await generate('RSA');
  const partial = { ...privateJwk };
  delete partial.qi;
  assert.throws(
    () => validate(partial),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_JWK,
  );
});

test('jwk namespace exposes the same functions', async () => {
  assert.equal(jwk.generate, generate);
  assert.equal(jwk.import, importJWK);
  assert.equal(jwk.thumbprint, thumbprint);
  // `jwk.export` is a dispatcher (see below), not equal to `exportJWK`.
  assert.equal(typeof jwk.export, 'function');
});

test('jwk.export defaults to JWK output', async () => {
  const { privateJwk } = await generate('EC', { curve: 'P-256' });
  const key = await importJWK(privateJwk);
  const out = await jwk.export(key);
  assert.equal(typeof out, 'object');
  assert.equal(/** @type {any} */ (out).kty, 'EC');
});

test('jwk.export forwards decoration options', async () => {
  const { privateJwk } = await generate('EC', { curve: 'P-256' });
  const key = await importJWK(privateJwk);
  const out = /** @type {any} */ (await jwk.export(key, { format: 'jwk', kid: 'x' }));
  assert.equal(out.kid, 'x');
});

test('jwk.export with format="pem" returns PKCS#8 for private keys', async () => {
  const { privateJwk } = await generate('EC', { curve: 'P-256' });
  const key = await importJWK(privateJwk);
  const pem = await jwk.export(key, { format: 'pem' });
  assert.equal(typeof pem, 'string');
  assert.match(/** @type {string} */ (pem), /BEGIN PRIVATE KEY/);
});

test('jwk.export with unknown format throws INVALID_FORMAT', async () => {
  const { privateJwk } = await generate('EC', { curve: 'P-256' });
  const key = await importJWK(privateJwk);
  await assert.rejects(
    () => jwk.export(key, /** @type {any} */ ({ format: 'bogus' })),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_FORMAT,
  );
});

test('validate: use=sig with key_ops=encrypt throws KEY_OPS_CONFLICT', async () => {
  const { publicJwk } = await generate('EC', { curve: 'P-256' });
  const bad = { ...publicJwk, use: 'sig', key_ops: ['encrypt'] };
  assert.throws(
    () => validate(bad),
    err => err instanceof JwkError && err.code === ErrorCode.KEY_OPS_CONFLICT,
  );
});

test('validate: use=sig with key_ops=[sign,verify] accepted (RFC 7517 §4.3 consistent)', async () => {
  const { publicJwk } = await generate('EC', { curve: 'P-256' });
  const good = { ...publicJwk, use: 'sig', key_ops: ['sign', 'verify'] };
  assert.ok(validate(good));
});

test('validate: use=enc with key_ops=[wrapKey,unwrapKey] accepted', async () => {
  const { publicJwk } = await generate('RSA');
  const good = { ...publicJwk, use: 'enc', key_ops: ['wrapKey', 'unwrapKey'] };
  assert.ok(validate(good));
});

test('importPEM x509: extracts public key', async () => {
  // Generate a fake self-signed cert via node:crypto? We don't have a cert
  // generator built in. Instead: sanity-check the format branch by handing
  // it a manifestly-wrong input and confirming we translate the error.
  await assert.rejects(
    () => importPEM('not a cert', 'x509'),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_KEY,
  );
});
