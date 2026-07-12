import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generate,
  verify,
  generateUnsigned,
  verifyUnsigned,
  generateForSession,
  verifyForSession,
} from '../src/csrf/index.js';
import { SecurityError, ErrorCode } from '../src/index.js';

const SECRET = 'a'.repeat(48); // >= 32 bytes
const OTHER_SECRET = 'b'.repeat(48);

test('generate produces "<random>.<mac>" shape', () => {
  const t = generate(SECRET);
  assert.match(t, /^[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]+$/);
  assert.equal(t.split('.').length, 2);
});

test('generate is unpredictable (no two tokens equal)', () => {
  const s = new Set();
  for (let i = 0; i < 100; i++) s.add(generate(SECRET));
  assert.equal(s.size, 100);
});

test('verify accepts matching cookie + header', () => {
  const t = generate(SECRET);
  assert.equal(verify(t, t, SECRET), true);
});

test('verify rejects when cookie !== header', () => {
  const a = generate(SECRET);
  const b = generate(SECRET);
  assert.equal(verify(a, b, SECRET), false);
});

test('verify rejects tampered token (bit flip in random half)', () => {
  const t = generate(SECRET);
  const [rand, mac] = t.split('.');
  const flipped = rand.slice(0, -1) + (rand.slice(-1) === 'A' ? 'B' : 'A');
  const tampered = `${flipped}.${mac}`;
  assert.equal(verify(tampered, tampered, SECRET), false);
});

test('verify rejects tampered MAC', () => {
  const t = generate(SECRET);
  const [rand, mac] = t.split('.');
  const flipped = mac.slice(0, -1) + (mac.slice(-1) === 'A' ? 'B' : 'A');
  const tampered = `${rand}.${flipped}`;
  assert.equal(verify(tampered, tampered, SECRET), false);
});

test('verify rejects token minted under a different secret', () => {
  const t = generate(OTHER_SECRET);
  assert.equal(verify(t, t, SECRET), false);
});

test('verify rejects missing / empty / non-string input', () => {
  assert.equal(verify('', '', SECRET), false);
  assert.equal(verify(undefined, undefined, SECRET), false);
  assert.equal(verify(null, 'x', SECRET), false);
  assert.equal(verify(123, 'x', SECRET), false);
  assert.equal(verify('x', 456, SECRET), false);
});

test('verify rejects malformed token (no dot / trailing dot / leading dot)', () => {
  assert.equal(verify('noDotHere', 'noDotHere', SECRET), false);
  assert.equal(verify('trailing.', 'trailing.', SECRET), false);
  assert.equal(verify('.leading', '.leading', SECRET), false);
});

test('generate throws on missing / weak secret', () => {
  assert.throws(
    () => generate(undefined),
    e => e instanceof SecurityError && e.code === ErrorCode.INVALID_ARGUMENT,
  );
  assert.throws(
    () => generate('short'),
    e => e instanceof SecurityError && e.code === ErrorCode.INVALID_ARGUMENT,
  );
  assert.throws(
    () => generate(123),
    e => e instanceof SecurityError && e.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('generate honors options.length within bounds', () => {
  const t16 = generate(SECRET, { length: 16 });
  const t64 = generate(SECRET, { length: 64 });
  // base64url of 16 bytes ≈ 22 chars, of 64 bytes ≈ 86 chars
  assert.ok(t16.split('.')[0].length < t64.split('.')[0].length);
});

test('generate rejects out-of-range length', () => {
  assert.throws(() => generate(SECRET, { length: 8 }));
  assert.throws(() => generate(SECRET, { length: 200 }));
  assert.throws(() => generate(SECRET, { length: 12.5 }));
});

test('unsigned generate/verify roundtrip', () => {
  const t = generateUnsigned();
  assert.equal(verifyUnsigned(t, t), true);
  assert.equal(verifyUnsigned(t, generateUnsigned()), false);
  assert.equal(verifyUnsigned('', ''), false);
  assert.equal(verifyUnsigned(null, 'x'), false);
});

test('session-bound generate is deterministic per (sid, secret)', () => {
  const a = generateForSession('sid_1', SECRET);
  const b = generateForSession('sid_1', SECRET);
  assert.equal(a, b);
  const c = generateForSession('sid_2', SECRET);
  assert.notEqual(a, c);
  const d = generateForSession('sid_1', OTHER_SECRET);
  assert.notEqual(a, d);
});

test('session-bound verify accepts matching, rejects others', () => {
  const t = generateForSession('sid_1', SECRET);
  assert.equal(verifyForSession(t, 'sid_1', SECRET), true);
  assert.equal(verifyForSession(t, 'sid_2', SECRET), false);
  assert.equal(verifyForSession(t, 'sid_1', OTHER_SECRET), false);
  assert.equal(verifyForSession('nope', 'sid_1', SECRET), false);
  assert.equal(verifyForSession(t, '', SECRET), false);
  assert.equal(verifyForSession(null, 'sid_1', SECRET), false);
});

test('session-bound generate throws on empty sessionId', () => {
  assert.throws(() => generateForSession('', SECRET));
  assert.throws(() => generateForSession(123, SECRET));
});
