import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { signJson, verifyJson, JwsError, ErrorCode } from '../src/index.js';

// -- Helpers ---------------------------------------------------------

function ecP256() {
  return generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}
// -- Flattened form --------------------------------------------------

test('signJson (1 signer) emits flattened form', async () => {
  const secret = randomBytes(32);
  const jws = await signJson({ hi: 'there' }, [{ key: secret, options: { alg: 'HS256', kid: 'k1' } }]);
  assert.ok('signature' in jws, 'flattened has top-level signature');
  assert.ok(!('signatures' in jws), 'flattened does not carry signatures array');
  assert.equal(typeof jws.protected, 'string');
  assert.equal(typeof jws.payload, 'string');
});

test('verifyJson (flattened) roundtrip', async () => {
  const secret = randomBytes(32);
  const jws = await signJson({ hi: 'there' }, [{ key: secret, options: { alg: 'HS256', kid: 'k1' } }]);
  const { header, payload, matchedSignatureIndex } = await verifyJson(jws, secret, {
    alg: ['HS256'],
  });
  assert.equal(header.alg, 'HS256');
  assert.equal(header.kid, 'k1');
  assert.deepEqual(payload, { hi: 'there' });
  assert.equal(matchedSignatureIndex, 0);
});

test('signJson: unprotected header lands on the emitted signature', async () => {
  const secret = randomBytes(32);
  const jws = await signJson({ x: 1 }, [{ key: secret, options: { alg: 'HS256', unprotected: { source: 'admin' } } }]);
  assert.deepEqual(/** @type {any} */ (jws).header, { source: 'admin' });
});

// -- General form ----------------------------------------------------

test('signJson (2 signers) emits general form', async () => {
  const secret = randomBytes(32);
  const { privateKey } = ecP256();
  const jws = await signJson({ hi: 'there' }, [
    { key: secret, options: { alg: 'HS256', kid: 'k1' } },
    { key: privateKey, options: { alg: 'ES256', kid: 'k2' } },
  ]);
  assert.ok(Array.isArray(/** @type {any} */ (jws).signatures));
  assert.equal(/** @type {any} */ (jws).signatures.length, 2);
});

test('verifyJson (general) — matches on the first signature by kid', async () => {
  const secret = randomBytes(32);
  const { privateKey } = ecP256();
  const jws = await signJson({ hi: 'there' }, [
    { key: secret, options: { alg: 'HS256', kid: 'hs1' } },
    { key: privateKey, options: { alg: 'ES256', kid: 'ec1' } },
  ]);
  const jwksLike = [
    // supplied as a "JWKS-like" array of keys with kid — resolver looks up hs1
    { kty: 'oct', k: secret.toString('base64url'), kid: 'hs1' },
    { kty: 'EC', crv: 'P-256', x: 'ignored', y: 'ignored', kid: 'nothing' },
  ];
  // Actually resolver picks by kid — only hs1 matches.
  const { matchedSignatureIndex, payload, header } = await verifyJson(jws, jwksLike, {
    alg: ['HS256', 'ES256'],
  });
  assert.equal(matchedSignatureIndex, 0);
  assert.equal(header.alg, 'HS256');
  assert.deepEqual(payload, { hi: 'there' });
});

test('verifyJson (general) — one tampered signature is skipped, the good one wins', async () => {
  const secret = randomBytes(32);
  const { publicKey, privateKey } = ecP256();
  const jws = /** @type {any} */ (
    await signJson({ x: 1 }, [
      { key: secret, options: { alg: 'HS256', kid: 'hs1' } },
      { key: privateKey, options: { alg: 'ES256', kid: 'ec1' } },
    ])
  );
  // Tamper with signature 0.
  const sigBuf = Buffer.from(jws.signatures[0].signature, 'base64url');
  sigBuf[0] ^= 0xff;
  jws.signatures[0].signature = sigBuf.toString('base64url');

  // Feed both keys; verify should skip the tampered HS256 and land on ES256.
  const { matchedSignatureIndex, header } = await verifyJson(
    jws,
    [
      { kty: 'oct', k: secret.toString('base64url'), kid: 'hs1' },
      // ES256 public JWK
      ...[publicKey.export({ format: 'jwk' })].map(j => ({ ...j, kid: 'ec1' })),
    ],
    { alg: ['HS256', 'ES256'] },
  );
  assert.equal(matchedSignatureIndex, 1);
  assert.equal(header.alg, 'ES256');
});

test('verifyJson (general): all-bad set fails with INVALID_SIGNATURE-family error', async () => {
  const secret = randomBytes(32);
  const jws = /** @type {any} */ (await signJson({ x: 1 }, [{ key: secret, options: { alg: 'HS256', kid: 'k' } }]));
  const sigBuf = Buffer.from(jws.signature, 'base64url');
  sigBuf[0] ^= 0xff;
  jws.signature = sigBuf.toString('base64url');
  await assert.rejects(
    () => verifyJson(jws, secret, { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_SIGNATURE,
  );
});

// -- Security surface ------------------------------------------------

test('signJson: alg "none" refused with ALGORITHM_NONE_FORBIDDEN', async () => {
  await assert.rejects(
    () => signJson({}, [{ key: randomBytes(32), options: { alg: 'none' } }]),
    err => err instanceof JwsError && err.code === ErrorCode.ALGORITHM_NONE_FORBIDDEN,
  );
});

test('verifyJson: missing allowlist raises MISSING_ALG_ALLOWLIST', async () => {
  const secret = randomBytes(32);
  const jws = await signJson({}, [{ key: secret, options: { alg: 'HS256' } }]);
  await assert.rejects(
    () => verifyJson(jws, secret, /** @type {any} */ (undefined)),
    err => err instanceof JwsError && err.code === ErrorCode.MISSING_ALG_ALLOWLIST,
  );
});

test('verifyJson: alg not in allowlist raises ALGORITHM_MISMATCH', async () => {
  const secret = randomBytes(32);
  const jws = await signJson({}, [{ key: secret, options: { alg: 'HS256' } }]);
  await assert.rejects(
    () => verifyJson(jws, secret, { alg: ['RS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.ALGORITHM_MISMATCH,
  );
});

// -- Shape guards ----------------------------------------------------

test('signJson: empty signers array raises INVALID_ARGUMENT', async () => {
  await assert.rejects(
    () => signJson({}, []),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('signJson: signer missing options raises INVALID_ARGUMENT', async () => {
  await assert.rejects(
    () => signJson({}, [/** @type {any} */ ({ key: randomBytes(32) })]),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('verifyJson: non-object payload raises INVALID_TOKEN', async () => {
  await assert.rejects(
    () => verifyJson(/** @type {any} */ ('string'), randomBytes(32), { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_TOKEN,
  );
});

test('verifyJson: neither `signatures` nor `signature` present → INVALID_TOKEN', async () => {
  await assert.rejects(
    () =>
      verifyJson(
        /** @type {any} */ ({ payload: Buffer.from('{}').toString('base64url'), protected: 'e30' }),
        randomBytes(32),
        { alg: ['HS256'] },
      ),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_TOKEN,
  );
});
