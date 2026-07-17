import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { sign, verify, peek, decode, JwtError, ErrorCode, jwt } from '../src/index.js';

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

// Algorithm matrix roundtrip
test('HS256: sign + verify roundtrip (Buffer secret)', async () => {
  const secret = randomBytes(32);
  const token = await sign({ userId: 1 }, secret, { alg: 'HS256' });
  const { header, payload } = await verify(token, secret, { alg: ['HS256'] });
  assert.equal(header.alg, 'HS256');
  assert.equal(header.typ, 'JWT');
  assert.equal(payload.userId, 1);
  assert.equal(typeof payload.iat, 'number');
});

test('HS256: string secret (jsonwebtoken interop)', async () => {
  const secret = 'a-string-secret-thats-long-enough-32-bytes';
  const token = await sign({ x: 1 }, secret, { alg: 'HS256' });
  const { payload } = await verify(token, secret, { alg: ['HS256'] });
  assert.equal(payload.x, 1);
});

test('HS256: too-short secret rejected with INVALID_KEY', async () => {
  await assert.rejects(
    () => sign({}, randomBytes(16), { alg: 'HS256' }),
    err => err instanceof JwtError && err.code === ErrorCode.INVALID_KEY,
  );
});

test('RS256: KeyObject roundtrip', async () => {
  const { publicKey, privateKey } = rsa2048();
  const token = await sign({ user: 'u1' }, privateKey, { alg: 'RS256', kid: 'k1' });
  const { header, payload, kid } = await verify(token, publicKey, { alg: ['RS256'] });
  assert.equal(header.kid, 'k1');
  assert.equal(kid, 'k1');
  assert.equal(payload.user, 'u1');
});

test('RS256: PEM string input (fs.readFileSync shape)', async () => {
  const { publicKey, privateKey } = rsa2048();
  const priv = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const pub = publicKey.export({ type: 'spki', format: 'pem' });
  const token = await sign({ x: 1 }, priv, { alg: 'RS256' });
  const { payload } = await verify(token, pub, { alg: ['RS256'] });
  assert.equal(payload.x, 1);
});

test('PS256: sign + verify roundtrip', async () => {
  const { publicKey, privateKey } = rsa2048();
  const token = await sign({ x: 1 }, privateKey, { alg: 'PS256' });
  const { payload } = await verify(token, publicKey, { alg: ['PS256'] });
  assert.equal(payload.x, 1);
});

test('ES256: sign + verify roundtrip', async () => {
  const { publicKey, privateKey } = ecP256();
  const token = await sign({ foo: 'bar' }, privateKey, { alg: 'ES256' });
  const { payload } = await verify(token, publicKey, { alg: ['ES256'] });
  assert.equal(payload.foo, 'bar');
});

test('EdDSA (Ed25519): sign + verify roundtrip', async () => {
  const { publicKey, privateKey } = ed25519();
  const token = await sign({ ok: true }, privateKey, { alg: 'EdDSA' });
  const { payload } = await verify(token, publicKey, { alg: ['EdDSA'] });
  assert.equal(payload.ok, true);
});

// Claims injection (phase 3 basic)
test('sign: iat auto-injected as NumericDate', async () => {
  const before = Math.floor(Date.now() / 1000);
  const secret = randomBytes(32);
  const token = await sign({ x: 1 }, secret, { alg: 'HS256' });
  const { payload } = await verify(token, secret, { alg: ['HS256'] });
  assert.equal(typeof payload.iat, 'number');
  assert.ok(payload.iat >= before);
});

test('sign: noTimestamp:true skips iat', async () => {
  const secret = randomBytes(32);
  const token = await sign({ x: 1 }, secret, { alg: 'HS256', noTimestamp: true });
  const { payload } = await verify(token, secret, { alg: ['HS256'] });
  assert.equal(payload.iat, undefined);
});

test('sign: expiresIn "15m" injects exp', async () => {
  const secret = randomBytes(32);
  const token = await sign({ x: 1 }, secret, { alg: 'HS256', expiresIn: '15m' });
  const { payload } = await verify(token, secret, { alg: ['HS256'] });
  assert.equal(typeof payload.exp, 'number');
  assert.equal(payload.exp - payload.iat, 900);
});

test('verify: expired token → TOKEN_EXPIRED', async () => {
  const secret = randomBytes(32);
  const token = await sign({ x: 1 }, secret, { alg: 'HS256', expiresIn: -3600 });
  await assert.rejects(
    () => verify(token, secret, { alg: ['HS256'] }),
    err => err instanceof JwtError && err.code === ErrorCode.TOKEN_EXPIRED,
  );
});

test('verify: nbf in future → TOKEN_NOT_YET_VALID', async () => {
  const secret = randomBytes(32);
  const token = await sign({ x: 1 }, secret, { alg: 'HS256', notBefore: '5m' });
  await assert.rejects(
    () => verify(token, secret, { alg: ['HS256'] }),
    err => err instanceof JwtError && err.code === ErrorCode.TOKEN_NOT_YET_VALID,
  );
});

test('sign: claim shortcuts (issuer / audience / subject / nonce)', async () => {
  const secret = randomBytes(32);
  const token = await sign({}, secret, {
    alg: 'HS256',
    issuer: 'https://api.example.com',
    audience: 'myapp',
    subject: 'user-42',
    nonce: 'abc123',
  });
  const { payload } = await verify(token, secret, { alg: ['HS256'] });
  assert.equal(payload.iss, 'https://api.example.com');
  assert.equal(payload.aud, 'myapp');
  assert.equal(payload.sub, 'user-42');
  assert.equal(payload.nonce, 'abc123');
});

test('sign: jwtId: true → hex jti', async () => {
  const secret = randomBytes(32);
  const token = await sign({}, secret, { alg: 'HS256', jwtId: true });
  const { payload } = await verify(token, secret, { alg: ['HS256'] });
  assert.equal(typeof payload.jti, 'string');
  assert.equal(payload.jti.length, 32); // 16 bytes hex
});

test('sign: custom jwtId function', async () => {
  const secret = randomBytes(32);
  const token = await sign({}, secret, {
    alg: 'HS256',
    jwtId: async () => 'req_custom_id',
  });
  const { payload } = await verify(token, secret, { alg: ['HS256'] });
  assert.equal(payload.jti, 'req_custom_id');
});

// typ enforcement (RFC 9068)
test('sign: default typ is JWT', async () => {
  const secret = randomBytes(32);
  const token = await sign({ x: 1 }, secret, { alg: 'HS256' });
  const { header } = decode(token);
  assert.equal(header.typ, 'JWT');
});

test('sign: typ override for RFC 9068 access tokens', async () => {
  const secret = randomBytes(32);
  const token = await sign({ x: 1 }, secret, { alg: 'HS256', typ: 'at+jwt' });
  const { header } = decode(token);
  assert.equal(header.typ, 'at+jwt');
});

test('verify: typ mismatch → INVALID_TYP', async () => {
  const secret = randomBytes(32);
  const token = await sign({ x: 1 }, secret, { alg: 'HS256', typ: 'at+jwt' });
  await assert.rejects(
    () => verify(token, secret, { alg: ['HS256'], typ: 'JWT' }),
    err => err instanceof JwtError && err.code === ErrorCode.INVALID_TYP,
  );
});

// Metadata return
test('sign: returnMetadata gives { token, jti, expiresAt, issuedAt, alg, kid }', async () => {
  const secret = randomBytes(32);
  const result = await sign({ x: 1 }, secret, {
    alg: 'HS256',
    kid: 'k1',
    expiresIn: '15m',
    jwtId: true,
    returnMetadata: true,
  });
  assert.equal(typeof result, 'object');
  assert.equal(typeof result.token, 'string');
  assert.equal(result.alg, 'HS256');
  assert.equal(result.kid, 'k1');
  assert.equal(typeof result.jti, 'string');
  assert.ok(result.expiresAt instanceof Date);
  assert.ok(result.issuedAt instanceof Date);
});

// Security surface
test('sign: alg "none" refused with ALGORITHM_NONE_FORBIDDEN', async () => {
  await assert.rejects(
    () => sign({}, randomBytes(32), { alg: 'none' }),
    err => err instanceof JwtError && err.code === ErrorCode.ALGORITHM_NONE_FORBIDDEN,
  );
});

test('verify: alg none token refused unconditionally', async () => {
  const encHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' }), 'utf8').toString('base64url');
  const encPayload = Buffer.from(JSON.stringify({ x: 1 }), 'utf8').toString('base64url');
  const token = `${encHeader}.${encPayload}.`;
  await assert.rejects(
    () => verify(token, randomBytes(32), { alg: ['HS256'] }),
    err => err instanceof JwtError && err.code === ErrorCode.ALGORITHM_NONE_FORBIDDEN,
  );
});

test('verify: missing options raises MISSING_ALG_ALLOWLIST', async () => {
  const secret = randomBytes(32);
  const token = await sign({}, secret, { alg: 'HS256' });
  await assert.rejects(
    () => verify(token, secret, /** @type {any} */ (undefined)),
    err => err instanceof JwtError && err.code === ErrorCode.MISSING_ALG_ALLOWLIST,
  );
});

test('verify: alg mismatch → ALGORITHM_MISMATCH', async () => {
  const secret = randomBytes(32);
  const token = await sign({}, secret, { alg: 'HS256' });
  await assert.rejects(
    () => verify(token, secret, { alg: ['RS256'] }),
    err => err instanceof JwtError && err.code === ErrorCode.ALGORITHM_MISMATCH,
  );
});

// peek
test('peek: verifies signature but skips claim checks', async () => {
  const secret = randomBytes(32);
  const expiredToken = await sign({ userId: 42 }, secret, { alg: 'HS256', expiresIn: -3600 });
  // verify rejects expired
  await assert.rejects(
    () => verify(expiredToken, secret, { alg: ['HS256'] }),
    err => err.code === ErrorCode.TOKEN_EXPIRED,
  );
  // peek accepts
  const { payload } = await peek(expiredToken, secret, { alg: ['HS256'] });
  assert.equal(payload.userId, 42);
});

test('peek: still refuses invalid signature', async () => {
  const secret = randomBytes(32);
  const token = await sign({}, secret, { alg: 'HS256' });
  const parts = token.split('.');
  const sigBuf = Buffer.from(parts[2], 'base64url');
  sigBuf[0] ^= 0xff;
  const tampered = `${parts[0]}.${parts[1]}.${sigBuf.toString('base64url')}`;
  await assert.rejects(
    () => peek(tampered, secret, { alg: ['HS256'] }),
    err => err instanceof JwtError && err.code === ErrorCode.INVALID_SIGNATURE,
  );
});

// decode
test('decode: parses header + payload + signature (UNSAFE)', async () => {
  const secret = randomBytes(32);
  const token = await sign({ hi: 'there' }, secret, {
    alg: 'HS256',
    kid: 'k1',
    expiresIn: '15m',
  });
  const { header, payload, signature } = decode(token);
  assert.equal(header.alg, 'HS256');
  assert.equal(header.kid, 'k1');
  assert.equal(payload.hi, 'there');
  assert.equal(typeof payload.exp, 'number');
  assert.ok(Buffer.isBuffer(signature) && signature.length === 32);
});

// Namespace
test('jwt namespace exposes sign/verify/peek/decode', () => {
  assert.equal(jwt.sign, sign);
  assert.equal(jwt.verify, verify);
  assert.equal(jwt.peek, peek);
  assert.equal(jwt.decode, decode);
});
