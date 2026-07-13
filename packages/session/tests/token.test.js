import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateSessionId, encodeToken, decodeToken } from '../src/token.js';
import { SessionError, ErrorCode } from '../src/errors.js';
import { seal } from '@exortek/crypto';

const SECRET = 'thirty-two-byte-secret-for-session-tests';

test('generateSessionId: base64url, unique', () => {
  const a = generateSessionId();
  const b = generateSessionId();
  assert.match(a, /^[A-Za-z0-9_-]+$/);
  assert.notEqual(a, b);
});

test('encode + decode roundtrip', () => {
  const now = 1_000_000_000_000;
  const payload = {
    sid: 'sid-abc',
    uid: 'u1',
    claims: { roles: ['admin'] },
    iat: now,
    exp: now + 60_000,
  };
  const token = encodeToken(payload, SECRET, { now });
  const decoded = decodeToken(token, SECRET, { now });
  assert.equal(decoded.sid, 'sid-abc');
  assert.equal(decoded.uid, 'u1');
  assert.deepEqual(decoded.claims, { roles: ['admin'] });
});

test('encode refuses payload whose exp is not in the future', () => {
  const now = 1_000_000_000_000;
  assert.throws(
    () => encodeToken({ sid: 's', uid: null, claims: {}, iat: now, exp: now - 1 }, SECRET, { now }),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('decode raises EXPIRED past the token TTL', () => {
  const now = 1_000_000_000_000;
  const token = encodeToken({ sid: 's', uid: null, claims: {}, iat: now, exp: now + 1000 }, SECRET, { now });
  assert.throws(
    () => decodeToken(token, SECRET, { now: now + 60_000 }),
    err => err instanceof SessionError && err.code === ErrorCode.EXPIRED,
  );
});

test('decode raises INVALID_TOKEN on tampering', () => {
  const now = 1_000_000_000_000;
  const token = encodeToken({ sid: 's', uid: null, claims: {}, iat: now, exp: now + 60_000 }, SECRET, { now });
  const tampered = token.slice(0, -3) + 'AAA';
  assert.throws(
    () => decodeToken(tampered, SECRET, { now }),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_TOKEN,
  );
});

test('decode raises INVALID_TOKEN on wrong secret', () => {
  const now = 1_000_000_000_000;
  const token = encodeToken({ sid: 's', uid: null, claims: {}, iat: now, exp: now + 60_000 }, SECRET, { now });
  assert.throws(
    () => decodeToken(token, 'thirty-two-byte-DIFFERENT-secret-here-y', { now }),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_TOKEN,
  );
});

test('decode walks an array of secrets (rotation)', () => {
  const now = 1_000_000_000_000;
  const OLD = 'thirty-two-byte-OLD-secret-goes-here-ok';
  const NEW = 'thirty-two-byte-NEW-secret-goes-here-ok';
  const token = encodeToken({ sid: 's', uid: null, claims: {}, iat: now, exp: now + 60_000 }, OLD, { now });
  const decoded = decodeToken(token, [NEW, OLD], { now });
  assert.equal(decoded.sid, 's');
});

test('decode: rejects non-string / empty inputs', () => {
  assert.throws(() => decodeToken('', SECRET));
  assert.throws(() => decodeToken(null, SECRET));
  assert.throws(() => decodeToken(undefined, SECRET));
});

test('decode: rejects payloads without sid', () => {
  // Craft a valid seal with a wrong-shape payload. encodeToken enforces
  // sid; we bypass it by hitting seal directly.
  const now = 1_000_000_000_000;
  const token = seal({ not: 'a session' }, SECRET, { ttl: 60, now });
  assert.throws(
    () => decodeToken(token, SECRET, { now }),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_TOKEN,
  );
});
