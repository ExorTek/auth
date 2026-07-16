import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { sign, verify, JwsError, ErrorCode } from '../src/index.js';

// Helpers
function rsa2048() {
  return generateKeyPairSync('rsa', { modulusLength: 2048 });
}

function _b64uJson(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

// CVE-2015-9235 — algorithm confusion (RSA public key as HMAC secret)
test('CVE-2015-9235: HS256 token forged with RSA public key as secret is refused', async () => {
  // Attacker takes an RSA public key that the server uses to verify RS256
  // tokens, wraps it in a token signed with HS256 using the public key
  // bytes as an HMAC secret. A vulnerable verifier will happily accept.
  // We refuse at the key boundary because verifying an HS256 token requires
  // an HMAC secret, not an RSA `KeyObject`.
  const { publicKey } = rsa2048();
  const secretBytes = publicKey.export({ type: 'spki', format: 'pem' });
  const token = await sign({ user: 'legit' }, Buffer.from(secretBytes), { alg: 'HS256' });

  await assert.rejects(
    () => verify(token, publicKey, { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_KEY,
  );
});

test('CVE-2015-9235: HS256 token forged against a JWK RSA public also rejected', async () => {
  const { publicKey } = rsa2048();
  const rsaJwk = publicKey.export({ format: 'jwk' });
  // Build a well-shaped token so parsing succeeds — the key boundary
  // is where the alg-confusion attempt has to die.
  const encHeader = _b64uJson({ alg: 'HS256' });
  const encPayload = _b64uJson({ x: 1 });
  const encSig = Buffer.alloc(32).toString('base64url');
  const token = `${encHeader}.${encPayload}.${encSig}`;

  await assert.rejects(
    () => verify(token, rsaJwk, { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_KEY,
  );
});

// CVE-2015-2951 — `alg: none` acceptance
test('CVE-2015-2951: alg "none" token refused unconditionally on verify', async () => {
  const encHeader = _b64uJson({ alg: 'none' });
  const encPayload = _b64uJson({ user: 'attacker', role: 'admin' });
  const forged = `${encHeader}.${encPayload}.`;

  await assert.rejects(
    () => verify(forged, randomBytes(32), { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.ALGORITHM_NONE_FORBIDDEN,
  );
});

test('CVE-2015-2951: alg "None" (mixed case) still refused', async () => {
  const encHeader = _b64uJson({ alg: 'None' });
  const encPayload = _b64uJson({ x: 1 });
  const forged = `${encHeader}.${encPayload}.`;
  await assert.rejects(
    () => verify(forged, randomBytes(32), { alg: ['HS256'] }),
    // "None" isn't 'none' verbatim, but it's also not in the algorithm
    // table so lookup fails first with UNSUPPORTED_ALGORITHM after
    // allowlist check runs. In either shape the token is refused.
    err =>
      err instanceof JwsError &&
      (err.code === ErrorCode.ALGORITHM_MISMATCH ||
        err.code === ErrorCode.UNSUPPORTED_ALGORITHM ||
        err.code === ErrorCode.ALGORITHM_NONE_FORBIDDEN),
  );
});

test('CVE-2015-2951: sign side cannot emit alg "none" either', async () => {
  await assert.rejects(
    () => sign({}, randomBytes(32), { alg: 'none' }),
    err => err instanceof JwsError && err.code === ErrorCode.ALGORITHM_NONE_FORBIDDEN,
  );
});

// Silent allowlist omission
test('silent-allowlist regression: verify without options raises MISSING_ALG_ALLOWLIST', async () => {
  const secret = randomBytes(32);
  const token = await sign({}, secret, { alg: 'HS256' });
  await assert.rejects(
    () => verify(token, secret, /** @type {any} */ (undefined)),
    err => err instanceof JwsError && err.code === ErrorCode.MISSING_ALG_ALLOWLIST,
  );
});

test('silent-allowlist regression: verify with options but no alg key raises MISSING_ALG_ALLOWLIST', async () => {
  const secret = randomBytes(32);
  const token = await sign({}, secret, { alg: 'HS256' });
  await assert.rejects(
    () => verify(token, secret, /** @type {any} */ ({})),
    err => err instanceof JwsError && err.code === ErrorCode.MISSING_ALG_ALLOWLIST,
  );
});

// crit
test('crit: verify — unknown critical parameter refused with CRIT_UNSUPPORTED', async () => {
  // Hand-craft a header that lists an unknown critical parameter.
  const encHeader = _b64uJson({ alg: 'HS256', crit: ['app-role'], 'app-role': 'admin' });
  const encPayload = _b64uJson({ x: 1 });
  // Sign with the same secret so signature check passes.
  const secret = randomBytes(32);
  const { createHmac } = await import('node:crypto');
  const sig = createHmac('sha256', secret).update(`${encHeader}.${encPayload}`).digest('base64url');
  const forged = `${encHeader}.${encPayload}.${sig}`;

  await assert.rejects(
    () => verify(forged, secret, { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.CRIT_UNSUPPORTED,
  );
});

test('crit: verify — knownCriticalHeaders opt-in lets an app-known extension through', async () => {
  const encHeader = _b64uJson({ alg: 'HS256', crit: ['app-role'], 'app-role': 'admin' });
  const encPayload = _b64uJson({ x: 1 });
  const secret = randomBytes(32);
  const { createHmac } = await import('node:crypto');
  const sig = createHmac('sha256', secret).update(`${encHeader}.${encPayload}`).digest('base64url');
  const forged = `${encHeader}.${encPayload}.${sig}`;

  const { header } = await verify(forged, secret, {
    alg: ['HS256'],
    knownCriticalHeaders: ['app-role'],
  });
  assert.equal(header['app-role'], 'admin');
});

test('crit: verify — listed parameter must actually appear in the header', async () => {
  const encHeader = _b64uJson({ alg: 'HS256', crit: ['b64'] }); // no b64 member
  const encPayload = _b64uJson({});
  const secret = randomBytes(32);
  const { createHmac } = await import('node:crypto');
  const sig = createHmac('sha256', secret).update(`${encHeader}.${encPayload}`).digest('base64url');
  const forged = `${encHeader}.${encPayload}.${sig}`;
  await assert.rejects(
    () => verify(forged, secret, { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_HEADER,
  );
});

test('crit: verify — empty crit array is malformed → INVALID_HEADER', async () => {
  const encHeader = _b64uJson({ alg: 'HS256', crit: [] });
  const encPayload = _b64uJson({});
  const secret = randomBytes(32);
  const { createHmac } = await import('node:crypto');
  const sig = createHmac('sha256', secret).update(`${encHeader}.${encPayload}`).digest('base64url');
  await assert.rejects(
    () => verify(`${encHeader}.${encPayload}.${sig}`, secret, { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_HEADER,
  );
});

test('crit: verify — crit listing itself is malformed → INVALID_HEADER', async () => {
  const encHeader = _b64uJson({ alg: 'HS256', crit: ['crit'] });
  const encPayload = _b64uJson({});
  const secret = randomBytes(32);
  const { createHmac } = await import('node:crypto');
  const sig = createHmac('sha256', secret).update(`${encHeader}.${encPayload}`).digest('base64url');
  await assert.rejects(
    () => verify(`${encHeader}.${encPayload}.${sig}`, secret, { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_HEADER,
  );
});

// Header integrity
test('tamper: header bit-flip flips INVALID_SIGNATURE', async () => {
  const secret = randomBytes(32);
  const token = await sign({ x: 1 }, secret, { alg: 'HS256' });
  const parts = token.split('.');
  const headerBuf = Buffer.from(parts[0], 'base64url');
  headerBuf[0] ^= 0x01;
  const tampered = `${headerBuf.toString('base64url')}.${parts[1]}.${parts[2]}`;
  await assert.rejects(
    () => verify(tampered, secret, { alg: ['HS256'] }),
    err =>
      err instanceof JwsError && (err.code === ErrorCode.INVALID_SIGNATURE || err.code === ErrorCode.INVALID_HEADER),
  );
});

// Segment shape
test('token shape: empty header segment → INVALID_TOKEN', async () => {
  await assert.rejects(
    () => verify('.payload.sig', randomBytes(32), { alg: ['HS256'] }),
    err => err instanceof JwsError && (err.code === ErrorCode.INVALID_TOKEN || err.code === ErrorCode.INVALID_HEADER),
  );
});

test('token shape: header not a JSON object → INVALID_HEADER', async () => {
  const encHeader = Buffer.from(JSON.stringify(['array', 'not', 'object']), 'utf8').toString('base64url');
  const encPayload = _b64uJson({});
  const token = `${encHeader}.${encPayload}.sig`;
  await assert.rejects(
    () => verify(token, randomBytes(32), { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_HEADER,
  );
});

test('token shape: header alg is not a string → INVALID_HEADER', async () => {
  const encHeader = _b64uJson({ alg: 42 });
  const encPayload = _b64uJson({});
  const token = `${encHeader}.${encPayload}.sig`;
  await assert.rejects(
    () => verify(token, randomBytes(32), { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_HEADER,
  );
});

// HMAC key length
test('RFC 7518 §3.2: HS384 requires at least 48-byte secret', async () => {
  const shortSecret = randomBytes(32);
  await assert.rejects(
    () => sign({}, shortSecret, { alg: 'HS384' }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_KEY,
  );
});

test('RFC 7518 §3.2: HS512 requires at least 64-byte secret', async () => {
  const shortSecret = randomBytes(48);
  await assert.rejects(
    () => sign({}, shortSecret, { alg: 'HS512' }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_KEY,
  );
});

// DoS surface
test('DoS guard: token larger than 1 MB refused via maxTokenSize=1024', async () => {
  // Build an oversized token — just repeat a base64url char.
  const large = 'a'.repeat(2000);
  const bogus = `${large}.${large}.${large}`;
  await assert.rejects(
    () => verify(bogus, randomBytes(32), { alg: ['HS256'], maxTokenSize: 1024 }),
    err => err instanceof JwsError && err.code === ErrorCode.TOKEN_TOO_LARGE,
  );
});
