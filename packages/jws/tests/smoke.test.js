import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { jws, sign, verify, decode, decodeProtectedHeader, JwsError, ErrorCode } from '../src/index.js';

// -- Helpers ---------------------------------------------------------

function ecP256() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { publicKey, privateKey };
}
function rsa2048() {
  return generateKeyPairSync('rsa', { modulusLength: 2048 });
}
function ed25519() {
  return generateKeyPairSync('ed25519');
}

// -- Roundtrip: HS256 ------------------------------------------------

test('HS256: sign + verify roundtrip (KeyObject via Buffer)', async () => {
  const secret = randomBytes(32);
  const token = await sign({ hi: 'there' }, secret, { alg: 'HS256' });
  const { header, payload } = await verify(token, secret, { alg: ['HS256'] });
  assert.equal(header.alg, 'HS256');
  assert.deepEqual(payload, { hi: 'there' });
});

test('HS256: RFC 7518 §3.2 secret length is enforced', async () => {
  const short = randomBytes(16);
  await assert.rejects(
    () => sign({ x: 1 }, short, { alg: 'HS256' }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_KEY,
  );
});

// -- Roundtrip: RS256 / PS256 ----------------------------------------

test('RS256: sign + verify roundtrip', async () => {
  const { publicKey, privateKey } = rsa2048();
  const token = await sign({ user: 'u1' }, privateKey, { alg: 'RS256', kid: 'k1' });
  const { header, payload, kid } = await verify(token, publicKey, { alg: ['RS256'] });
  assert.equal(header.kid, 'k1');
  assert.equal(kid, 'k1');
  assert.equal(payload.user, 'u1');
});

test('PS256: sign + verify roundtrip', async () => {
  const { publicKey, privateKey } = rsa2048();
  const token = await sign({ x: 1 }, privateKey, { alg: 'PS256' });
  const { payload } = await verify(token, publicKey, { alg: ['PS256'] });
  assert.deepEqual(payload, { x: 1 });
});

// -- Roundtrip: ES256 / EdDSA ----------------------------------------

test('ES256: sign + verify roundtrip (raw R||S conversion)', async () => {
  const { publicKey, privateKey } = ecP256();
  const token = await sign({ foo: 'bar' }, privateKey, { alg: 'ES256' });
  const { payload } = await verify(token, publicKey, { alg: ['ES256'] });
  assert.deepEqual(payload, { foo: 'bar' });
});

test('EdDSA (Ed25519): sign + verify roundtrip', async () => {
  const { publicKey, privateKey } = ed25519();
  const token = await sign({ ok: true }, privateKey, { alg: 'EdDSA' });
  const { payload } = await verify(token, publicKey, { alg: ['EdDSA'] });
  assert.deepEqual(payload, { ok: true });
});

// -- Security: `none` refused ----------------------------------------

test('sign: alg "none" refused with ALGORITHM_NONE_FORBIDDEN', async () => {
  await assert.rejects(
    () => sign({}, randomBytes(32), { alg: 'none' }),
    err => err instanceof JwsError && err.code === ErrorCode.ALGORITHM_NONE_FORBIDDEN,
  );
});

test('verify: token that claims alg "none" refused before allowlist check', async () => {
  const encHeader = Buffer.from(JSON.stringify({ alg: 'none' }), 'utf8').toString('base64url');
  const encPayload = Buffer.from(JSON.stringify({ x: 1 }), 'utf8').toString('base64url');
  const noneToken = `${encHeader}.${encPayload}.`;
  await assert.rejects(
    () => verify(noneToken, randomBytes(32), { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.ALGORITHM_NONE_FORBIDDEN,
  );
});

// -- Security: allowlist ---------------------------------------------

test('verify: missing options raises MISSING_ALG_ALLOWLIST', async () => {
  const secret = randomBytes(32);
  const token = await sign({}, secret, { alg: 'HS256' });
  await assert.rejects(
    () => verify(token, secret, /** @type {any} */ (undefined)),
    err => err instanceof JwsError && err.code === ErrorCode.MISSING_ALG_ALLOWLIST,
  );
});

test('verify: options.alg = [] raises MISSING_ALG_ALLOWLIST', async () => {
  const secret = randomBytes(32);
  const token = await sign({}, secret, { alg: 'HS256' });
  await assert.rejects(
    () => verify(token, secret, { alg: [] }),
    err => err instanceof JwsError && err.code === ErrorCode.MISSING_ALG_ALLOWLIST,
  );
});

test('verify: token alg not in allowlist raises ALGORITHM_MISMATCH', async () => {
  const secret = randomBytes(32);
  const token = await sign({}, secret, { alg: 'HS256' });
  await assert.rejects(
    () => verify(token, secret, { alg: ['RS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.ALGORITHM_MISMATCH,
  );
});

// -- Security: tampering ---------------------------------------------

test('verify: signature bit-flip raises INVALID_SIGNATURE', async () => {
  const secret = randomBytes(32);
  const token = await sign({ x: 1 }, secret, { alg: 'HS256' });
  const parts = token.split('.');
  const sigBuf = Buffer.from(parts[2], 'base64url');
  sigBuf[0] ^= 0xff;
  const tampered = `${parts[0]}.${parts[1]}.${sigBuf.toString('base64url')}`;
  await assert.rejects(
    () => verify(tampered, secret, { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_SIGNATURE,
  );
});

test('verify: payload bit-flip raises INVALID_SIGNATURE', async () => {
  const secret = randomBytes(32);
  const token = await sign({ x: 1 }, secret, { alg: 'HS256' });
  const parts = token.split('.');
  const badPayload = Buffer.from(JSON.stringify({ x: 2 }), 'utf8').toString('base64url');
  await assert.rejects(
    () => verify(`${parts[0]}.${badPayload}.${parts[2]}`, secret, { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_SIGNATURE,
  );
});

test('verify: alg confusion — HS256 token verified with RSA public key fails', async () => {
  const { publicKey } = rsa2048();
  const secret = randomBytes(32);
  const token = await sign({ x: 1 }, secret, { alg: 'HS256' });
  await assert.rejects(
    () => verify(token, publicKey, { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_KEY,
  );
});

// -- Token shape -----------------------------------------------------

test('verify: truncated token raises INVALID_TOKEN', async () => {
  await assert.rejects(
    () => verify('a.b', randomBytes(32), { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_TOKEN,
  );
});

test('verify: extra dot raises INVALID_TOKEN', async () => {
  await assert.rejects(
    () => verify('a.b.c.d', randomBytes(32), { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_TOKEN,
  );
});

test('verify: non-base64url part raises INVALID_TOKEN', async () => {
  await assert.rejects(
    () => verify('a=.b=.c=', randomBytes(32), { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_TOKEN,
  );
});

// -- maxTokenSize -----------------------------------------------------

test('verify: maxTokenSize enforced', async () => {
  const secret = randomBytes(32);
  const token = await sign({ x: 1 }, secret, { alg: 'HS256' });
  await assert.rejects(
    () => verify(token, secret, { alg: ['HS256'], maxTokenSize: 4 }),
    err => err instanceof JwsError && err.code === ErrorCode.TOKEN_TOO_LARGE,
  );
});

// -- decode ----------------------------------------------------------

test('decode: parses header + payload + signature without verification', async () => {
  const secret = randomBytes(32);
  const token = await sign({ hi: 'there' }, secret, { alg: 'HS256', kid: 'k' });
  const d = decode(token);
  assert.equal(d.header.alg, 'HS256');
  assert.equal(d.header.kid, 'k');
  assert.deepEqual(d.payload, { hi: 'there' });
  assert.ok(Buffer.isBuffer(d.signature) && d.signature.length === 32);
});

test('decode: raw-bytes payload preserved', async () => {
  const secret = randomBytes(32);
  const raw = Buffer.from('hello');
  const token = await sign(raw, secret, { alg: 'HS256' });
  const d = decode(token);
  // Payload isn't valid JSON — decode falls back to bytes.
  assert.ok(Buffer.isBuffer(d.payload));
  assert.equal(d.payload.toString('utf8'), 'hello');
});

test('decodeProtectedHeader: kid extraction', async () => {
  const { publicKey, privateKey } = ecP256();
  const token = await sign({ x: 1 }, privateKey, { alg: 'ES256', kid: 'my-kid' });
  const h = decodeProtectedHeader(token);
  assert.equal(h.kid, 'my-kid');
  // sanity — verify still works after inspection
  await verify(token, publicKey, { alg: ['ES256'] });
});

// -- Namespace -------------------------------------------------------

test('jws namespace exposes sign/verify/decode', () => {
  assert.equal(jws.sign, sign);
  assert.equal(jws.verify, verify);
  assert.equal(jws.decode, decode);
});
