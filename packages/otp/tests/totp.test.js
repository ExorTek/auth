import { test } from 'node:test';
import assert from 'node:assert/strict';
import { totp, verifyTotp, remainingSeconds, OtpError } from '../src/index.js';

// RFC 6238 Appendix B — official test vectors.
// SHA-1 uses 20-byte ASCII "12345678901234567890"
// SHA-256 uses 32-byte ASCII "12345678901234567890123456789012"
// SHA-512 uses 64-byte ASCII "1234567890...1234"
// The Appendix specifies an 8-digit output.

// RFC 6238 Appendix B specifies the raw HMAC keys as printable ASCII.
// We pass them directly as Buffers so the test isolates the algorithm
// from the base32 codec — separate secret.test.js covers encoding.
const SHA1_SECRET = Buffer.from('12345678901234567890', 'ascii');
const SHA256_SECRET = Buffer.from('12345678901234567890123456789012', 'ascii');
const SHA512_SECRET = Buffer.from('1234567890123456789012345678901234567890123456789012345678901234', 'ascii');

// (T, expected code) per RFC 6238 Appendix B.
// Timestamps below are in seconds — we multiply by 1000 for our API.
const RFC_6238_VECTORS = [
  { t: 59, sha1: '94287082', sha256: '46119246', sha512: '90693936' },
  { t: 1111111109, sha1: '07081804', sha256: '68084774', sha512: '25091201' },
  { t: 1111111111, sha1: '14050471', sha256: '67062674', sha512: '99943326' },
  { t: 1234567890, sha1: '89005924', sha256: '91819424', sha512: '93441116' },
  { t: 2000000000, sha1: '69279037', sha256: '90698825', sha512: '38618901' },
];

for (const v of RFC_6238_VECTORS) {
  test(`totp: RFC 6238 vector T=${v.t} SHA1 → ${v.sha1}`, () => {
    const code = totp(SHA1_SECRET, {
      digits: 8,
      period: 30,
      algorithm: 'SHA1',
      timestamp: v.t * 1000,
    });
    assert.equal(code, v.sha1);
  });
  test(`totp: RFC 6238 vector T=${v.t} SHA256 → ${v.sha256}`, () => {
    const code = totp(SHA256_SECRET, {
      digits: 8,
      period: 30,
      algorithm: 'SHA256',
      timestamp: v.t * 1000,
    });
    assert.equal(code, v.sha256);
  });
  test(`totp: RFC 6238 vector T=${v.t} SHA512 → ${v.sha512}`, () => {
    const code = totp(SHA512_SECRET, {
      digits: 8,
      period: 30,
      algorithm: 'SHA512',
      timestamp: v.t * 1000,
    });
    assert.equal(code, v.sha512);
  });
}

test('totp: 6-digit default', () => {
  const code = totp(SHA1_SECRET, { timestamp: 59 * 1000 });
  assert.equal(code.length, 6);
  assert.equal(code, '287082'); // last 6 of the 94287082 vector
});

test('verifyTotp: accepts codes inside the ±window slop', async () => {
  const t = 1234567890 * 1000;
  const code = totp(SHA1_SECRET, { digits: 8, timestamp: t });
  // The same code should verify at t-15s and t+15s (within the 30s period).
  assert.equal(
    await verifyTotp(code, SHA1_SECRET, {
      digits: 8,
      timestamp: t - 15_000,
      window: 1,
    }),
    true,
  );
  assert.equal(
    await verifyTotp(code, SHA1_SECRET, {
      digits: 8,
      timestamp: t + 15_000,
      window: 1,
    }),
    true,
  );
  // Codes 2 periods away should NOT verify with window: 1.
  assert.equal(
    await verifyTotp(code, SHA1_SECRET, {
      digits: 8,
      timestamp: t + 90_000,
      window: 1,
    }),
    false,
  );
});

test('verifyTotp: rejects wrong code', async () => {
  const t = 1234567890 * 1000;
  assert.equal(await verifyTotp('00000000', SHA1_SECRET, { digits: 8, timestamp: t }), false);
  assert.equal(await verifyTotp('', SHA1_SECRET, { timestamp: t }), false);
  assert.equal(await verifyTotp(null, SHA1_SECRET, { timestamp: t }), false);
});

test('verifyTotp: window: 0 is strict', async () => {
  const t = 1234567890 * 1000;
  const code = totp(SHA1_SECRET, { digits: 8, timestamp: t });
  // At t + 15s the same period still — passes.
  assert.equal(
    await verifyTotp(code, SHA1_SECRET, {
      digits: 8,
      timestamp: t + 15_000,
      window: 0,
    }),
    true,
  );
  // 31 seconds later we're in the next period — fails.
  assert.equal(
    await verifyTotp(code, SHA1_SECRET, {
      digits: 8,
      timestamp: t + 31_000,
      window: 0,
    }),
    false,
  );
});

test('remainingSeconds: is in [1, period]', () => {
  // Fixed timestamps for determinism.
  for (const t of [59_000, 60_000, 89_999, 100_000]) {
    const r = remainingSeconds(30, t);
    assert.ok(r >= 1 && r <= 30, `remaining=${r} out of range`);
  }
});

test('remainingSeconds: exact period boundary', () => {
  // At exact 30s mark, we're 0 seconds into the new period — full window ahead.
  assert.equal(remainingSeconds(30, 30_000), 30);
});

test('verifyTotp: invalid window throws', async () => {
  await assert.rejects(() => verifyTotp('00000000', SHA1_SECRET, { window: -1 }), OtpError);
});

test('totp: t0 offset shifts the counter', () => {
  const t = 1_600_000_000_000; // ms
  const codeAtZero = totp(SHA1_SECRET, { timestamp: t, t0: 0 });
  // t0 == period means we skip exactly one counter forward.
  const codeAtPeriod = totp(SHA1_SECRET, { timestamp: t, t0: -30 });
  assert.notEqual(codeAtZero, codeAtPeriod);
});

test('verifyTotp: t0 is round-trip compatible', async () => {
  const t = 1_600_000_000_000;
  const t0 = 946_684_800; // Y2K epoch
  const code = totp(SHA1_SECRET, { timestamp: t, t0 });
  assert.equal(await verifyTotp(code, SHA1_SECRET, { timestamp: t, t0, window: 0 }), true);
});

test('totp: rejects non-finite t0', () => {
  assert.throws(() => totp(SHA1_SECRET, { t0: NaN }), OtpError);
  assert.throws(() => totp(SHA1_SECRET, { t0: Infinity }), OtpError);
});

test('hotp: SHA224 + SHA384 supported', async () => {
  const { hotp } = await import('../src/index.js');
  const c224 = hotp(SHA1_SECRET, 0, { algorithm: 'SHA224' });
  const c384 = hotp(SHA1_SECRET, 0, { algorithm: 'SHA384' });
  assert.equal(c224.length, 6);
  assert.equal(c384.length, 6);
});

// Regression: verifyTotp must accept the full documented window range
// [0, 10]. Previously any window > 5 threw "HOTP window must be an integer
// in [0, 10]" because the symmetric skew window (2×window) was routed
// through verifyHotp's forward-window guard.
test('verifyTotp: window 6..10 verify instead of throwing', async () => {
  const t = 1_600_000_000_000;
  const code = totp(SHA1_SECRET, { timestamp: t });
  for (const window of [6, 7, 8, 9, 10]) {
    assert.equal(
      await verifyTotp(code, SHA1_SECRET, { timestamp: t, window }),
      true,
      `window=${window} should verify the current code`,
    );
  }
});

test('verifyTotp: wide window accepts skewed codes within tolerance only', async () => {
  const t = 1_600_000_000_000;
  const period = 30;
  // A code from 6 periods in the future.
  const future = totp(SHA1_SECRET, { timestamp: t + 6 * period * 1000 });
  assert.equal(await verifyTotp(future, SHA1_SECRET, { timestamp: t, window: 6 }), true);
  // Just outside the window must still be rejected.
  assert.equal(await verifyTotp(future, SHA1_SECRET, { timestamp: t, window: 5 }), false);
});
