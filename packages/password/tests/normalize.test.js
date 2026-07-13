import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizePassword, MAX_PASSWORD_BYTES } from '../src/internal/normalize.js';
import { PasswordError, ErrorCode } from '../src/errors.js';

test('NFKC: composed and decomposed é hash to the same bytes', () => {
  const composed = normalizePassword('café');
  const decomposed = normalizePassword('café');
  assert.deepEqual(composed, decomposed);
});

test('rejects empty', () => {
  assert.throws(
    () => normalizePassword(''),
    err => err instanceof PasswordError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('rejects null byte', () => {
  assert.throws(
    () => normalizePassword('nul\0inside'),
    err => err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('rejects passwords over MAX_PASSWORD_BYTES', () => {
  const big = 'a'.repeat(MAX_PASSWORD_BYTES + 1);
  assert.throws(
    () => normalizePassword(big),
    err => err.code === ErrorCode.PASSWORD_TOO_LONG,
  );
});

test('accepts Buffer input', () => {
  const buf = Buffer.from('hello', 'utf8');
  assert.deepEqual(normalizePassword(buf), buf);
});

test('normalize: false disables Unicode normalization', () => {
  const composed = normalizePassword('café', { normalize: false });
  const decomposed = normalizePassword('café', { normalize: false });
  assert.notDeepEqual(composed, decomposed);
});

test('rejects non-string / non-buffer', () => {
  assert.throws(
    () => normalizePassword(42),
    err => err.code === ErrorCode.INVALID_ARGUMENT,
  );
  assert.throws(
    () => normalizePassword({}),
    err => err.code === ErrorCode.INVALID_ARGUMENT,
  );
});
