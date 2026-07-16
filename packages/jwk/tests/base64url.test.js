import { test } from 'node:test';
import assert from 'node:assert/strict';

import { encode, decode, decodeMember } from '../src/internal/base64url.js';
import { JwkError, ErrorCode } from '../src/index.js';

test('encode: empty buffer returns empty string', () => {
  assert.equal(encode(Buffer.alloc(0)), '');
});

test('encode: single byte encodes to 2 base64url chars', () => {
  assert.equal(encode(Buffer.from([0xff])), '_w');
});

test('encode: known vector (12 bytes ASCII)', () => {
  assert.equal(encode(Buffer.from('any carnal p')), 'YW55IGNhcm5hbCBw');
});

test('encode: Uint8Array (non-Buffer) accepted', () => {
  const u8 = new Uint8Array([1, 2, 3]);
  assert.equal(encode(u8), 'AQID');
});

test('encode: view over larger ArrayBuffer only encodes its slice', () => {
  const backing = new Uint8Array([9, 9, 1, 2, 3, 9, 9]);
  const view = new Uint8Array(backing.buffer, 2, 3); // [1, 2, 3]
  assert.equal(encode(view), 'AQID');
});

test('encode: throws INVALID_ARGUMENT on strings', () => {
  assert.throws(
    () => encode(/** @type {any} */ ('hello')),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('encode: throws INVALID_ARGUMENT on null / undefined', () => {
  assert.throws(
    () => encode(/** @type {any} */ (null)),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('decode: empty string returns empty buffer', () => {
  const buf = decode('');
  assert.equal(buf.length, 0);
});

test('decode: known vector', () => {
  assert.equal(decode('YW55IGNhcm5hbCBw').toString('utf8'), 'any carnal p');
});

test('decode: rejects padding `=`', () => {
  assert.throws(
    () => decode('YQ=='),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_FORMAT,
  );
});

test('decode: rejects `+` (base64 alphabet, not base64url)', () => {
  assert.throws(
    () => decode('a+b'),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_FORMAT,
  );
});

test('decode: rejects `/` (base64 alphabet, not base64url)', () => {
  assert.throws(
    () => decode('a/b'),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_FORMAT,
  );
});

test('decode: rejects whitespace', () => {
  assert.throws(
    () => decode('ab cd'),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_FORMAT,
  );
});

test('decode: rejects non-canonical encoding (roundtrip mismatch)', () => {
  // Single `A` decodes to zero bytes yet re-encodes to `""` — this
  // catches truncated / malformed inputs Node accepts silently.
  assert.throws(
    () => decode('A'),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_FORMAT,
  );
});

test('decode: rejects non-string input', () => {
  assert.throws(
    () => decode(/** @type {any} */ (123)),
    err => err instanceof JwkError && err.code === ErrorCode.INVALID_FORMAT,
  );
});

test('decodeMember: length mismatch throws INVALID_JWK with member name', () => {
  const bytes = encode(Buffer.alloc(16));
  try {
    decodeMember(bytes, 'EC.x', 32);
    assert.fail('should have thrown');
  } catch (err) {
    assert.ok(err instanceof JwkError);
    assert.equal(err.code, ErrorCode.INVALID_JWK);
    assert.match(err.message, /EC\.x/);
    assert.match(err.message, /32.*16|16.*32/);
  }
});

test('decodeMember: propagates INVALID_FORMAT as INVALID_JWK with member name', () => {
  try {
    decodeMember('a=b', 'RSA.n');
    assert.fail('should have thrown');
  } catch (err) {
    assert.ok(err instanceof JwkError);
    assert.equal(err.code, ErrorCode.INVALID_JWK);
    assert.match(err.message, /RSA\.n/);
  }
});

test('decodeMember: no length constraint accepts any length', () => {
  const bytes = encode(Buffer.from([1, 2, 3, 4]));
  const decoded = decodeMember(bytes, 'oct.k');
  assert.equal(decoded.length, 4);
});

test('encode / decode roundtrip: 256 random bytes', () => {
  const original = Buffer.alloc(256);
  for (let i = 0; i < 256; i++) original[i] = i;
  const roundtripped = decode(encode(original));
  assert.deepEqual(roundtripped, original);
});
