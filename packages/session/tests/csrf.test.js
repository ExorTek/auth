import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deriveCsrfToken, verifyCsrfToken, maskCsrfToken, unmaskCsrfToken } from '../src/csrf.js';
import { SessionError, ErrorCode } from '../src/errors.js';

const SECRET = 'thirty-two-byte-server-secret-for-csrf';

test('deriveCsrfToken: deterministic given same session + secret', () => {
  const a = deriveCsrfToken('sid-abc', SECRET);
  const b = deriveCsrfToken('sid-abc', SECRET);
  assert.equal(a, b);
});

test('deriveCsrfToken: different session → different token', () => {
  assert.notEqual(deriveCsrfToken('sid-abc', SECRET), deriveCsrfToken('sid-xyz', SECRET));
});

test('deriveCsrfToken: different secret → different token', () => {
  assert.notEqual(deriveCsrfToken('sid-abc', SECRET), deriveCsrfToken('sid-abc', 'other-secret'));
});

test('deriveCsrfToken: base64url only', () => {
  const t = deriveCsrfToken('sid-abc', SECRET);
  assert.match(t, /^[A-Za-z0-9_-]+$/);
  assert.equal(t.length, 32);
});

test('verifyCsrfToken: right token → true', () => {
  const t = deriveCsrfToken('sid-abc', SECRET);
  assert.equal(verifyCsrfToken(t, 'sid-abc', SECRET), true);
});

test('verifyCsrfToken: wrong token → false', () => {
  assert.equal(verifyCsrfToken('bogus', 'sid-abc', SECRET), false);
});

test('verifyCsrfToken: cross-session token → false', () => {
  const t = deriveCsrfToken('sid-abc', SECRET);
  assert.equal(verifyCsrfToken(t, 'sid-different', SECRET), false);
});

test('verifyCsrfToken: empty / non-string → false', () => {
  assert.equal(verifyCsrfToken('', 'sid', SECRET), false);
  assert.equal(verifyCsrfToken(null, 'sid', SECRET), false);
  assert.equal(verifyCsrfToken(42, 'sid', SECRET), false);
});

test('deriveCsrfToken: rejects empty sessionId', () => {
  assert.throws(
    () => deriveCsrfToken('', SECRET),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('deriveCsrfToken: rejects bad secret', () => {
  assert.throws(() => deriveCsrfToken('sid', null));
});

test('mask/unmask: round-trips and never repeats ciphertext (BREACH)', () => {
  const token = deriveCsrfToken('sid-1', SECRET);
  const m1 = maskCsrfToken(token);
  const m2 = maskCsrfToken(token);
  assert.notEqual(m1, m2, 'each mask must use a fresh pad');
  assert.equal(unmaskCsrfToken(m1), token);
  assert.equal(unmaskCsrfToken(m2), token);
  assert.equal(verifyCsrfToken(unmaskCsrfToken(m1), 'sid-1', SECRET), true);
});

test('unmask: returns null for malformed input, never throws', () => {
  assert.equal(unmaskCsrfToken(null), null);
  assert.equal(unmaskCsrfToken(''), null);
  assert.equal(unmaskCsrfToken('x'), null); // odd byte count after decode
  assert.equal(verifyCsrfToken(unmaskCsrfToken('x'), 'sid-1', SECRET), false);
});
