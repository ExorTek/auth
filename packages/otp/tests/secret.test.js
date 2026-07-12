import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateSecret, decodeSecret, OtpError } from '../src/index.js';

test('generateSecret: default 20 bytes base32, no padding', () => {
  const s = generateSecret();
  assert.match(s, /^[A-Z2-7]+$/);
  // 20 bytes = 160 bits, base32 without padding = ceil(160/5) = 32 chars
  assert.equal(s.length, 32);
});

test('generateSecret: unique on each call', () => {
  const a = generateSecret();
  const b = generateSecret();
  assert.notEqual(a, b);
});

test('generateSecret: custom byte size + padded output', () => {
  const s = generateSecret({ bytes: 32, encoding: 'base32padded' });
  // 32 bytes = 256 bits → 52 chars unpadded, 56 padded to multiple of 8.
  assert.equal(s.length, 56);
  assert.ok(s.endsWith('='));
});

test('generateSecret: hex encoding', () => {
  const s = generateSecret({ bytes: 20, encoding: 'hex' });
  assert.match(s, /^[0-9a-f]{40}$/);
});

test('generateSecret: rejects out-of-range byte count', () => {
  assert.throws(() => generateSecret({ bytes: 8 }), OtpError);
  assert.throws(() => generateSecret({ bytes: 500 }), OtpError);
  assert.throws(() => generateSecret({ bytes: 20.5 }), OtpError);
});

test('generateSecret: rejects unknown encoding', () => {
  assert.throws(() => generateSecret({ encoding: 'base99' }), OtpError);
});

test('decodeSecret: round-trip base32', () => {
  const s = generateSecret();
  const buf = decodeSecret(s);
  assert.equal(buf.length, 20);
});

test('decodeSecret: accepts lower-case + spaces (Google Authenticator paste style)', () => {
  const s = generateSecret();
  // Add spaces every 4 chars, lower-case.
  const pasteStyle = s
    .toLowerCase()
    .match(/.{1,4}/g)
    .join(' ');
  const buf = decodeSecret(pasteStyle);
  assert.equal(buf.length, 20);
});

test('decodeSecret: accepts Buffer / Uint8Array passthrough', () => {
  const raw = Buffer.from('12345678901234567890', 'ascii');
  assert.deepEqual(decodeSecret(raw), raw);
  const u8 = new Uint8Array(raw);
  assert.deepEqual(decodeSecret(u8), raw);
});

test('decodeSecret: accepts hex-only secret (0/1/8/9 disambiguate from base32)', () => {
  // Base32 alphabet is A-Z2-7 — using 0/1/8/9 forces the hex branch.
  const hex = '01020304050607080910111213141516171819aa';
  const buf = decodeSecret(hex);
  assert.equal(buf.length, 20);
});

test('decodeSecret: rejects garbage', () => {
  assert.throws(() => decodeSecret(''), OtpError);
  assert.throws(() => decodeSecret(null), OtpError);
  assert.throws(() => decodeSecret(123), OtpError);
  assert.throws(() => decodeSecret('!@#$%^&*()'), OtpError);
});
