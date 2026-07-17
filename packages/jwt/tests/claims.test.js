import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { sign, verify, JwtError, ErrorCode } from '../src/index.js';

const SECRET = randomBytes(32);

// clockTolerance
test('clockTolerance: expired within tolerance still passes', async () => {
  const token = await sign({ x: 1 }, SECRET, { alg: 'HS256', expiresIn: -30 });
  const { payload } = await verify(token, SECRET, { alg: ['HS256'], clockTolerance: 60 });
  assert.equal(payload.x, 1);
});

test('clockTolerance: nbf slightly in future within tolerance passes', async () => {
  const token = await sign({ x: 1 }, SECRET, { alg: 'HS256', notBefore: 30 });
  const { payload } = await verify(token, SECRET, { alg: ['HS256'], clockTolerance: '2m' });
  assert.equal(payload.x, 1);
});

// currentDate override (deterministic testing)
test('currentDate: use frozen "now" for deterministic verify', async () => {
  const token = await sign({ x: 1 }, SECRET, { alg: 'HS256', expiresIn: '15m' });
  const later = new Date(Date.now() + 60 * 60 * 1000);
  await assert.rejects(
    () => verify(token, SECRET, { alg: ['HS256'], currentDate: later }),
    err => err instanceof JwtError && err.code === ErrorCode.TOKEN_EXPIRED,
  );
});

// maxAge
test('maxAge: iat older than window → TOKEN_TOO_OLD', async () => {
  const token = await sign({ x: 1 }, SECRET, { alg: 'HS256' });
  // Wait a beat, then check with maxAge:0 (any iat is "too old")
  const later = new Date(Date.now() + 10000);
  await assert.rejects(
    () => verify(token, SECRET, { alg: ['HS256'], maxAge: 1, currentDate: later }),
    err => err instanceof JwtError && err.code === ErrorCode.TOKEN_TOO_OLD,
  );
});

test('maxAge: fresh token passes', async () => {
  const token = await sign({ x: 1 }, SECRET, { alg: 'HS256' });
  const { payload } = await verify(token, SECRET, { alg: ['HS256'], maxAge: '1h' });
  assert.equal(payload.x, 1);
});

test('maxAge: token missing iat → MISSING_CLAIM', async () => {
  const token = await sign({ x: 1 }, SECRET, { alg: 'HS256', noTimestamp: true });
  await assert.rejects(
    () => verify(token, SECRET, { alg: ['HS256'], maxAge: '1h' }),
    err => err instanceof JwtError && err.code === ErrorCode.MISSING_CLAIM,
  );
});

// sub — RFC 7519 §4.1.2 case-sensitive string
test('sub: non-string payload.sub → INVALID_SUBJECT', async () => {
  const enc = h => Buffer.from(JSON.stringify(h), 'utf8').toString('base64url');
  const encHeader = enc({ alg: 'HS256', typ: 'JWT' });
  const encPayload = enc({ sub: 12345, iat: Math.floor(Date.now() / 1000) });
  const { createHmac } = await import('node:crypto');
  const sig = createHmac('sha256', SECRET).update(`${encHeader}.${encPayload}`).digest('base64url');
  await assert.rejects(
    () => verify(`${encHeader}.${encPayload}.${sig}`, SECRET, { alg: ['HS256'] }),
    err => err instanceof JwtError && err.code === ErrorCode.INVALID_SUBJECT,
  );
});

test('sub: options.subject exact match required', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256', subject: 'user-42' });
  const { payload } = await verify(token, SECRET, { alg: ['HS256'], subject: 'user-42' });
  assert.equal(payload.sub, 'user-42');
  await assert.rejects(
    () => verify(token, SECRET, { alg: ['HS256'], subject: 'user-99' }),
    err => err instanceof JwtError && err.code === ErrorCode.INVALID_SUBJECT,
  );
});

// issuer — string / RegExp / array / async predicate
test('issuer: exact string match', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256', issuer: 'https://api.example.com' });
  await verify(token, SECRET, { alg: ['HS256'], issuer: 'https://api.example.com' });
  await assert.rejects(
    () => verify(token, SECRET, { alg: ['HS256'], issuer: 'https://other.example.com' }),
    err => err instanceof JwtError && err.code === ErrorCode.INVALID_ISSUER,
  );
});

test('issuer: RegExp match', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256', issuer: 'tenant-a.myapp.com' });
  await verify(token, SECRET, { alg: ['HS256'], issuer: /\.myapp\.com$/ });
});

test('issuer: array of options', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256', issuer: 'tenant-b' });
  await verify(token, SECRET, { alg: ['HS256'], issuer: ['tenant-a', 'tenant-b'] });
  await assert.rejects(
    () => verify(token, SECRET, { alg: ['HS256'], issuer: ['tenant-c', 'tenant-d'] }),
    err => err.code === ErrorCode.INVALID_ISSUER,
  );
});

test('issuer: async predicate fn', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256', issuer: 'https://legit.com' });
  await verify(token, SECRET, {
    alg: ['HS256'],
    issuer: async claimed => claimed.startsWith('https://'),
  });
  await assert.rejects(
    () =>
      verify(token, SECRET, {
        alg: ['HS256'],
        issuer: async claimed => claimed.startsWith('ftp://'),
      }),
    err => err.code === ErrorCode.INVALID_ISSUER,
  );
});

test('issuer: missing iss when option set → INVALID_ISSUER', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256' });
  await assert.rejects(
    () => verify(token, SECRET, { alg: ['HS256'], issuer: 'expected' }),
    err => err.code === ErrorCode.INVALID_ISSUER,
  );
});

// audience — string OR array on payload; matcher string/RegExp/array/fn
test('audience: string payload aud, string option, exact match', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256', audience: 'myapp' });
  await verify(token, SECRET, { alg: ['HS256'], audience: 'myapp' });
});

test('audience: array payload aud (RFC 7519 §4.1.3), one entry matches', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256', audience: ['myapp', 'admin-panel'] });
  await verify(token, SECRET, { alg: ['HS256'], audience: 'admin-panel' });
});

test('audience: RegExp matcher against array', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256', audience: ['tenant-a:api', 'tenant-b:api'] });
  await verify(token, SECRET, { alg: ['HS256'], audience: /^tenant-a:/ });
});

test('audience: async predicate', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256', audience: 'my-api' });
  await verify(token, SECRET, {
    alg: ['HS256'],
    audience: async v => v.endsWith('-api'),
  });
});

test('audience: no matching entry → INVALID_AUDIENCE', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256', audience: ['a', 'b'] });
  await assert.rejects(
    () => verify(token, SECRET, { alg: ['HS256'], audience: 'c' }),
    err => err.code === ErrorCode.INVALID_AUDIENCE,
  );
});

test('audience: missing aud when option set → INVALID_AUDIENCE', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256' });
  await assert.rejects(
    () => verify(token, SECRET, { alg: ['HS256'], audience: 'expected' }),
    err => err.code === ErrorCode.INVALID_AUDIENCE,
  );
});

// nonce
test('nonce: exact match required', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256', nonce: 'nonce-123' });
  await verify(token, SECRET, { alg: ['HS256'], nonce: 'nonce-123' });
  await assert.rejects(
    () => verify(token, SECRET, { alg: ['HS256'], nonce: 'wrong' }),
    err => err.code === ErrorCode.INVALID_NONCE,
  );
});

// requiredClaims
test('requiredClaims: all present → OK', async () => {
  const token = await sign({ userId: 1, role: 'admin' }, SECRET, {
    alg: 'HS256',
    subject: 'u1',
    jwtId: true,
  });
  await verify(token, SECRET, {
    alg: ['HS256'],
    requiredClaims: ['sub', 'jti', 'userId', 'role'],
  });
});

test('requiredClaims: missing claim → MISSING_CLAIM', async () => {
  const token = await sign({ userId: 1 }, SECRET, { alg: 'HS256' });
  await assert.rejects(
    () => verify(token, SECRET, { alg: ['HS256'], requiredClaims: ['sub'] }),
    err => err.code === ErrorCode.MISSING_CLAIM,
  );
});

// requiredScopes
test('requiredScopes: OAuth2 space-separated scope claim', async () => {
  const token = await sign({ scope: 'read:users write:posts admin' }, SECRET, { alg: 'HS256' });
  await verify(token, SECRET, {
    alg: ['HS256'],
    requiredScopes: ['read:users', 'admin'],
  });
});

test('requiredScopes: scp array claim', async () => {
  const token = await sign({ scp: ['read:users', 'admin'] }, SECRET, { alg: 'HS256' });
  await verify(token, SECRET, { alg: ['HS256'], requiredScopes: ['admin'] });
});

test('requiredScopes: missing scope → INSUFFICIENT_SCOPE', async () => {
  const token = await sign({ scope: 'read:users' }, SECRET, { alg: 'HS256' });
  await assert.rejects(
    () => verify(token, SECRET, { alg: ['HS256'], requiredScopes: ['write:users'] }),
    err => err.code === ErrorCode.INSUFFICIENT_SCOPE,
  );
});

// typ array
test('typ: accept multiple candidate values', async () => {
  const token = await sign({}, SECRET, { alg: 'HS256', typ: 'at+jwt' });
  await verify(token, SECRET, { alg: ['HS256'], typ: ['JWT', 'at+jwt'] });
});
