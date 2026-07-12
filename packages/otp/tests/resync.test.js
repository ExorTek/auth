import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hotp, resynchronize, OtpError } from '../src/index.js';

const SECRET = 'JBSWY3DPEHPK3PXP';

test('resynchronize: finds the drifted counter from two consecutive codes', () => {
  // Simulate a hardware token stuck at counter 137.
  const c1 = hotp(SECRET, 137);
  const c2 = hotp(SECRET, 138);
  const next = resynchronize(SECRET, [c1, c2], {
    startCounter: 100,
    maxLookAhead: 100,
  });
  assert.equal(next, 139); // advance past the pair
});

test('resynchronize: returns null when the pair does not match', () => {
  const c1 = hotp(SECRET, 137);
  // Second code is NOT consecutive.
  const c2 = hotp(SECRET, 999);
  const next = resynchronize(SECRET, [c1, c2], {
    startCounter: 100,
    maxLookAhead: 200,
  });
  assert.equal(next, null);
});

test('resynchronize: refuses drift beyond maxLookAhead', () => {
  const c1 = hotp(SECRET, 500);
  const c2 = hotp(SECRET, 501);
  const next = resynchronize(SECRET, [c1, c2], {
    startCounter: 0,
    maxLookAhead: 50,
  });
  assert.equal(next, null);
});

test('resynchronize: rejects malformed input', () => {
  assert.throws(() => resynchronize(SECRET, ['123456']), OtpError);
  assert.throws(() => resynchronize(SECRET, ['a', 'b', 'c']), OtpError);
  assert.throws(() => resynchronize(SECRET, [], { maxLookAhead: 10 }), OtpError);
  assert.equal(resynchronize(SECRET, [null, undefined]), null);
});

test('resynchronize: honors digits + algorithm', () => {
  const c1 = hotp(SECRET, 50, { digits: 8, algorithm: 'SHA256' });
  const c2 = hotp(SECRET, 51, { digits: 8, algorithm: 'SHA256' });
  const next = resynchronize(SECRET, [c1, c2], {
    startCounter: 40,
    digits: 8,
    algorithm: 'SHA256',
  });
  assert.equal(next, 52);
});
