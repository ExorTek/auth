import { test } from 'node:test';
import assert from 'node:assert/strict';

import { encode, encodeString, encodeJson, decode, decodeToString, decodeJson } from '../src/base64url.js';

test('encode: Buffer round-trip', () => {
  const bytes = Buffer.from([0, 1, 2, 254, 255]);
  const encoded = encode(bytes);
  assert.match(encoded, /^[A-Za-z0-9_-]+$/);
  assert.deepEqual(decode(encoded), bytes);
});

test('encode: Uint8Array round-trip', () => {
  const bytes = new Uint8Array([9, 8, 7, 250]);
  assert.deepEqual(decode(encode(bytes)), Buffer.from(bytes));
});

test('encode: rejects non-Buffer / non-Uint8Array', () => {
  assert.throws(() => encode(null), TypeError);
  assert.throws(() => encode('str'), TypeError);
  assert.throws(() => encode(42), TypeError);
});

test('encodeString / decodeToString round-trip', () => {
  const text = 'hello 🌍 — RFC 4648';
  assert.equal(decodeToString(encodeString(text)), text);
});

test('encodeJson / decodeJson round-trip', () => {
  const value = { a: 1, b: ['x', null, true], c: 'ü' };
  assert.deepEqual(decodeJson(encodeJson(value)), value);
});

test('decode: rejects standard base64 padding', () => {
  assert.throws(() => decode('YQ=='), /alphabet/);
});

test('decode: rejects `+` and `/` (standard base64 characters)', () => {
  assert.throws(() => decode('a+b'), /alphabet/);
  assert.throws(() => decode('a/b'), /alphabet/);
});

test('decode: rejects non-canonical encoding via roundtrip check', () => {
  // 'a' alone is not a canonical unpadded base64url — decoding + re-encoding produces ''.
  assert.throws(() => decode('a'), /canonical/);
});

test('decode: rejects non-string input', () => {
  assert.throws(() => decode(42), TypeError);
  assert.throws(() => decode(null), TypeError);
});

test('decodeJson: propagates JSON.parse failure as an Error', () => {
  const notJson = encodeString('not-json:{');
  assert.throws(() => decodeJson(notJson), /JSON/);
});
