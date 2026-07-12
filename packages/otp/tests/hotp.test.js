import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hotp, verifyHotp, OtpError } from '../src/index.js';

// RFC 4226 Appendix D — official test vectors.
//   Secret: "12345678901234567890" (ASCII, 20 bytes)
//   → base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
const RFC_SECRET_BASE32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

const RFC_4226_VECTORS = [
  { counter: 0, code: '755224' },
  { counter: 1, code: '287082' },
  { counter: 2, code: '359152' },
  { counter: 3, code: '969429' },
  { counter: 4, code: '338314' },
  { counter: 5, code: '254676' },
  { counter: 6, code: '287922' },
  { counter: 7, code: '162583' },
  { counter: 8, code: '399871' },
  { counter: 9, code: '520489' },
];

for (const { counter, code } of RFC_4226_VECTORS) {
  test(`hotp: RFC 4226 vector counter=${counter} → ${code}`, () => {
    assert.equal(hotp(RFC_SECRET_BASE32, counter), code);
  });
}

test('hotp: accepts Buffer secret', () => {
  const buf = Buffer.from('12345678901234567890', 'ascii');
  assert.equal(hotp(buf, 0), '755224');
});

test('hotp: honors 7- and 8-digit widths', () => {
  const c7 = hotp(RFC_SECRET_BASE32, 0, { digits: 7 });
  const c8 = hotp(RFC_SECRET_BASE32, 0, { digits: 8 });
  assert.equal(c7.length, 7);
  assert.equal(c8.length, 8);
  // The suffix stays consistent (dynamic truncation is deterministic).
  assert.equal(c7.slice(-6), '755224');
  assert.equal(c8.slice(-6), '755224');
});

test('hotp: rejects invalid arguments', () => {
  assert.throws(() => hotp(RFC_SECRET_BASE32, -1), OtpError);
  assert.throws(() => hotp(RFC_SECRET_BASE32, 1.5), OtpError);
  assert.throws(() => hotp(RFC_SECRET_BASE32, 0, { digits: 5 }), OtpError);
  assert.throws(() => hotp(RFC_SECRET_BASE32, 0, { algorithm: 'MD5' }), OtpError);
});

test('verifyHotp: exact match returns the counter', () => {
  assert.equal(verifyHotp('755224', RFC_SECRET_BASE32, 0, { window: 0 }), 0);
});

test('verifyHotp: window advances counter when caller is behind', () => {
  // Server thinks counter is 3, but user's client advanced to 5.
  const matched = verifyHotp('254676', RFC_SECRET_BASE32, 3, { window: 3 });
  assert.equal(matched, 5);
});

test('verifyHotp: returns null on mismatch', () => {
  assert.equal(verifyHotp('000000', RFC_SECRET_BASE32, 0, { window: 5 }), null);
});

test('verifyHotp: rejects wrong-length / non-numeric', () => {
  assert.equal(verifyHotp('7552', RFC_SECRET_BASE32, 0), null);
  assert.equal(verifyHotp('ABCDEF', RFC_SECRET_BASE32, 0), null);
  assert.equal(verifyHotp('', RFC_SECRET_BASE32, 0), null);
  assert.equal(verifyHotp(null, RFC_SECRET_BASE32, 0), null);
});

test('verifyHotp: rejects invalid window', () => {
  assert.throws(() => verifyHotp('755224', RFC_SECRET_BASE32, 0, { window: -1 }), OtpError);
  assert.throws(() => verifyHotp('755224', RFC_SECRET_BASE32, 0, { window: 100 }), OtpError);
});

test('hotp: 9- and 10-digit widths (Bitwarden / 1Password compat)', () => {
  const c9 = hotp(RFC_SECRET_BASE32, 0, { digits: 9 });
  const c10 = hotp(RFC_SECRET_BASE32, 0, { digits: 10 });
  assert.equal(c9.length, 9);
  assert.equal(c10.length, 10);
});

test('hotp: rejects digits above 10', () => {
  assert.throws(() => hotp(RFC_SECRET_BASE32, 0, { digits: 11 }), OtpError);
});

test('hotp: SHA256 + SHA512 emit stable codes', () => {
  // Same secret, same counter, different algorithms.
  const c1 = hotp(RFC_SECRET_BASE32, 0, { algorithm: 'SHA1' });
  const c256 = hotp(RFC_SECRET_BASE32, 0, { algorithm: 'SHA256' });
  const c512 = hotp(RFC_SECRET_BASE32, 0, { algorithm: 'SHA512' });
  assert.equal(c1, '755224');
  assert.equal(c1.length, 6);
  assert.equal(c256.length, 6);
  assert.equal(c512.length, 6);
  assert.notEqual(c1, c256);
  assert.notEqual(c256, c512);
});
