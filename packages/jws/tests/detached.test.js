import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { signDetached, verifyDetached, verify, JwsError, ErrorCode } from '../src/index.js';

// -- Helpers ---------------------------------------------------------

function ecP256() {
  return generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}

// -- Roundtrip -------------------------------------------------------

test('detached: HS256 roundtrip preserves payload bytes', async () => {
  const secret = randomBytes(32);
  const payload = Buffer.from('a long body that never gets base64ed twice');
  const { token, detached } = await signDetached(payload, secret, { alg: 'HS256' });
  assert.equal(token.split('.').length, 3);
  assert.equal(token.split('.')[1], '', 'payload segment must be empty');
  assert.deepEqual(detached, payload);

  const { payload: back } = await verifyDetached(token, detached, secret, { alg: ['HS256'] });
  assert.deepEqual(back, payload);
});

test('detached: ES256 roundtrip', async () => {
  const { publicKey, privateKey } = ecP256();
  const payload = Buffer.from('detached ec');
  const { token, detached } = await signDetached(payload, privateKey, { alg: 'ES256' });
  const { header, payload: back } = await verifyDetached(token, detached, publicKey, {
    alg: ['ES256'],
  });
  assert.equal(header.alg, 'ES256');
  assert.deepEqual(back, payload);
});

test('detached: kid + header decoration flows through', async () => {
  const { publicKey, privateKey } = ecP256();
  const payload = Buffer.from('x');
  const { token, detached } = await signDetached(payload, privateKey, {
    alg: 'ES256',
    kid: 'kid-42',
    header: { typ: 'JWT' },
  });
  const { header, kid } = await verifyDetached(token, detached, publicKey, { alg: ['ES256'] });
  assert.equal(header.kid, 'kid-42');
  assert.equal(header.typ, 'JWT');
  assert.equal(kid, 'kid-42');
});

// -- Payload substitution --------------------------------------------

test('detached: substituting a different payload flips INVALID_SIGNATURE', async () => {
  const secret = randomBytes(32);
  const { token } = await signDetached(Buffer.from('trusted'), secret, { alg: 'HS256' });
  await assert.rejects(
    () => verifyDetached(token, Buffer.from('impostor'), secret, { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_SIGNATURE,
  );
});

test('detached: swapping just one payload byte flips INVALID_SIGNATURE', async () => {
  const secret = randomBytes(32);
  const orig = Buffer.from('short body');
  const { token, detached } = await signDetached(orig, secret, { alg: 'HS256' });
  const tampered = Buffer.from(detached);
  tampered[0] ^= 0x01;
  await assert.rejects(
    () => verifyDetached(token, tampered, secret, { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_SIGNATURE,
  );
});

// -- Shape guards ----------------------------------------------------

test('signDetached: non-Buffer payload raises INVALID_PAYLOAD', async () => {
  await assert.rejects(
    () => signDetached(/** @type {any} */ ('a string'), randomBytes(32), { alg: 'HS256' }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_PAYLOAD,
  );
});

test('verifyDetached: non-Buffer payload raises INVALID_PAYLOAD', async () => {
  const secret = randomBytes(32);
  const { token } = await signDetached(Buffer.from('x'), secret, { alg: 'HS256' });
  await assert.rejects(
    () => verifyDetached(token, /** @type {any} */ ('string not bytes'), secret, { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_PAYLOAD,
  );
});

test('verifyDetached: token with non-empty payload segment raises INVALID_TOKEN', async () => {
  const secret = randomBytes(32);
  // Sign attached, then use verifyDetached — payload segment isn't empty.
  const attached = await (await import('../src/sign.js')).sign({ x: 1 }, secret, { alg: 'HS256' });
  await assert.rejects(
    () => verifyDetached(attached, Buffer.from('anything'), secret, { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_TOKEN,
  );
});

// -- Security surface applies to detached, too -----------------------

test('signDetached: alg "none" refused with ALGORITHM_NONE_FORBIDDEN', async () => {
  await assert.rejects(
    () => signDetached(Buffer.from('x'), randomBytes(32), { alg: 'none' }),
    err => err instanceof JwsError && err.code === ErrorCode.ALGORITHM_NONE_FORBIDDEN,
  );
});

test('verifyDetached: missing options raises MISSING_ALG_ALLOWLIST', async () => {
  const secret = randomBytes(32);
  const { token, detached } = await signDetached(Buffer.from('x'), secret, { alg: 'HS256' });
  await assert.rejects(
    () => verifyDetached(token, detached, secret, /** @type {any} */ (undefined)),
    err => err instanceof JwsError && err.code === ErrorCode.MISSING_ALG_ALLOWLIST,
  );
});

test('verifyDetached: alg not in allowlist raises ALGORITHM_MISMATCH', async () => {
  const secret = randomBytes(32);
  const { token, detached } = await signDetached(Buffer.from('x'), secret, { alg: 'HS256' });
  await assert.rejects(
    () => verifyDetached(token, detached, secret, { alg: ['RS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.ALGORITHM_MISMATCH,
  );
});

// -- Cross-mode isolation --------------------------------------------

test('verify (attached) rejects a detached token — empty payload → INVALID_SIGNATURE', async () => {
  const secret = randomBytes(32);
  const { token } = await signDetached(Buffer.from('x'), secret, { alg: 'HS256' });
  // verify() sees the empty payload segment and hashes `header.` (empty payload) —
  // which will not match the signature computed over the real payload bytes.
  await assert.rejects(
    () => verify(token, secret, { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_SIGNATURE,
  );
});
