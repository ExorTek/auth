import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { sign, verify, JwtError, ErrorCode } from '../src/index.js';

const SECRET = randomBytes(32);
const _b64uJson = v => Buffer.from(JSON.stringify(v), 'utf8').toString('base64url');

// CVE-2015-9235 — algorithm confusion (RSA public key as HMAC secret)
test('CVE-2015-9235: RSA public key as HMAC secret is refused at key boundary', async () => {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
  // Attacker forges an HS256 token using the RSA public key as the HMAC
  // secret. A vulnerable verifier would happily accept.
  const forged = await sign({ role: 'admin' }, Buffer.from(pubPem), { alg: 'HS256' });
  // Legit server expects RS256 with the RSA public key.
  await assert.rejects(
    () => verify(forged, publicKey, { alg: ['HS256'] }),
    err => err instanceof JwtError && err.code === ErrorCode.INVALID_KEY,
  );
});

// CVE-2015-2951 — alg:'none' acceptance
test('CVE-2015-2951: alg:"none" token refused unconditionally on verify', async () => {
  const encHeader = _b64uJson({ alg: 'none', typ: 'JWT' });
  const encPayload = _b64uJson({ role: 'admin' });
  const forged = `${encHeader}.${encPayload}.`;
  await assert.rejects(
    () => verify(forged, SECRET, { alg: ['HS256'] }),
    err => err instanceof JwtError && err.code === ErrorCode.ALGORITHM_NONE_FORBIDDEN,
  );
});

test('CVE-2015-2951: sign cannot emit alg:"none" either', async () => {
  await assert.rejects(
    () => sign({}, SECRET, { alg: 'none' }),
    err => err instanceof JwtError && err.code === ErrorCode.ALGORITHM_NONE_FORBIDDEN,
  );
});

test('CVE-2015-2951: mixed-case "None" also refused', async () => {
  const encHeader = _b64uJson({ alg: 'None', typ: 'JWT' });
  const encPayload = _b64uJson({});
  const forged = `${encHeader}.${encPayload}.`;
  await assert.rejects(
    () => verify(forged, SECRET, { alg: ['HS256'] }),
    err =>
      err instanceof JwtError &&
      (err.code === ErrorCode.ALGORITHM_MISMATCH ||
        err.code === ErrorCode.UNSUPPORTED_ALGORITHM ||
        err.code === ErrorCode.ALGORITHM_NONE_FORBIDDEN),
  );
});

// Silent-allowlist regression class
test('silent-allowlist: verify without options raises MISSING_ALG_ALLOWLIST', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256' });
  await assert.rejects(
    () => verify(token, SECRET, /** @type {any} */ (undefined)),
    err => err.code === ErrorCode.MISSING_ALG_ALLOWLIST,
  );
});

test('silent-allowlist: verify with { alg: [] } raises MISSING_ALG_ALLOWLIST', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256' });
  await assert.rejects(
    () => verify(token, SECRET, { alg: [] }),
    err => err.code === ErrorCode.MISSING_ALG_ALLOWLIST,
  );
});

test('silent-allowlist: allowlist without token alg raises ALGORITHM_MISMATCH', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256' });
  await assert.rejects(
    () => verify(token, SECRET, { alg: ['RS256'] }),
    err => err.code === ErrorCode.ALGORITHM_MISMATCH,
  );
});

// Tamper detection
test('tamper: signature bit-flip → INVALID_SIGNATURE', async () => {
  const token = await sign({ x: 1 }, SECRET, { alg: 'HS256' });
  const parts = token.split('.');
  const sig = Buffer.from(parts[2], 'base64url');
  sig[0] ^= 0xff;
  await assert.rejects(
    () =>
      verify(`${parts[0]}.${parts[1]}.${sig.toString('base64url')}`, SECRET, {
        alg: ['HS256'],
      }),
    err => err.code === ErrorCode.INVALID_SIGNATURE,
  );
});

test('tamper: payload bit-flip → INVALID_SIGNATURE', async () => {
  const token = await sign({ x: 1 }, SECRET, { alg: 'HS256' });
  const parts = token.split('.');
  const badPayload = _b64uJson({ x: 2 });
  await assert.rejects(
    () => verify(`${parts[0]}.${badPayload}.${parts[2]}`, SECRET, { alg: ['HS256'] }),
    err => err.code === ErrorCode.INVALID_SIGNATURE,
  );
});

test('tamper: header bit-flip → INVALID_SIGNATURE (or INVALID_HEADER for structural break)', async () => {
  const token = await sign({ x: 1 }, SECRET, { alg: 'HS256' });
  const parts = token.split('.');
  const badHeader = _b64uJson({ alg: 'HS256', typ: 'JWT', extra: 'attacker' });
  await assert.rejects(
    () => verify(`${badHeader}.${parts[1]}.${parts[2]}`, SECRET, { alg: ['HS256'] }),
    err => err.code === ErrorCode.INVALID_SIGNATURE || err.code === ErrorCode.INVALID_HEADER,
  );
});

// Shape guards
test('shape: truncated token (2 dots missing) → INVALID_TOKEN', async () => {
  await assert.rejects(
    () => verify('a.b', SECRET, { alg: ['HS256'] }),
    err => err.code === ErrorCode.INVALID_TOKEN,
  );
});

test('shape: extra dot → INVALID_TOKEN', async () => {
  await assert.rejects(
    () => verify('a.b.c.d', SECRET, { alg: ['HS256'] }),
    err => err.code === ErrorCode.INVALID_TOKEN,
  );
});

test('shape: non-base64url segment → INVALID_TOKEN', async () => {
  await assert.rejects(
    () => verify('a=.b=.c=', SECRET, { alg: ['HS256'] }),
    err => err.code === ErrorCode.INVALID_TOKEN,
  );
});

test('shape: header not a JSON object → INVALID_HEADER', async () => {
  const encHeader = Buffer.from(JSON.stringify(['array']), 'utf8').toString('base64url');
  const encPayload = _b64uJson({});
  await assert.rejects(
    () => verify(`${encHeader}.${encPayload}.sig`, SECRET, { alg: ['HS256'] }),
    err => err.code === ErrorCode.INVALID_HEADER,
  );
});

test('shape: payload not a JSON object → INVALID_PAYLOAD', async () => {
  const encHeader = _b64uJson({ alg: 'HS256', typ: 'JWT' });
  const encPayload = Buffer.from(JSON.stringify(['array']), 'utf8').toString('base64url');
  const { createHmac } = await import('node:crypto');
  const sig = createHmac('sha256', SECRET).update(`${encHeader}.${encPayload}`).digest('base64url');
  await assert.rejects(
    () => verify(`${encHeader}.${encPayload}.${sig}`, SECRET, { alg: ['HS256'] }),
    err => err.code === ErrorCode.INVALID_PAYLOAD,
  );
});

// Key material minimums (RFC 7518 §3.2 / §3.3 / §3.5)
test('RFC 7518 §3.2: HS384 refuses short secret (INVALID_KEY)', async () => {
  await assert.rejects(
    () => sign({}, randomBytes(32), { alg: 'HS384' }),
    err => err.code === ErrorCode.INVALID_KEY,
  );
});

test('RFC 7518 §3.2: HS256 refuses short-secret KeyObject (INVALID_KEY)', async () => {
  const { createSecretKey } = await import('node:crypto');
  const shortKey = createSecretKey(Buffer.from('x'));
  await assert.rejects(
    () => sign({}, shortKey, { alg: 'HS256' }),
    err => err.code === ErrorCode.INVALID_KEY,
  );
});

test('RFC 7518 §3.3: RS256 refuses RSA-1024 KeyObject (INVALID_KEY)', async () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
  await assert.rejects(
    () => sign({}, privateKey, { alg: 'RS256' }),
    err => err.code === ErrorCode.INVALID_KEY,
  );
});

// DoS
test('DoS: token above maxTokenSize refused before parsing', async () => {
  const big = 'a'.repeat(2000);
  const bogus = `${big}.${big}.${big}`;
  await assert.rejects(
    () => verify(bogus, SECRET, { alg: ['HS256'], maxTokenSize: 1024 }),
    err => err.code === ErrorCode.TOKEN_TOO_LARGE,
  );
});
