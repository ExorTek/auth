import { createHmac, timingSafeEqual } from 'node:crypto';
import { OtpError, ErrorCode } from './internal/errors.js';
import { truncate } from './internal/digits.js';
import { decodeSecret } from './secret.js';

// RFC 4226 / 6238 nominally specify SHA1, with 6238 explicitly opting
// SHA256 + SHA512 in. SHA224 + SHA384 aren't in the RFCs but share the
// exact same HMAC construction — enterprise flows using truncated SHA-2
// variants Just Work.
const SUPPORTED_ALGORITHMS = Object.freeze(new Set(['SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512']));

/**
 * @typedef {'SHA1' | 'SHA224' | 'SHA256' | 'SHA384' | 'SHA512'} OtpAlgorithm
 */

/**
 * @typedef {object} HotpOptions
 * @property {6 | 7 | 8 | 9 | 10} [digits=6]
 *   Length of the emitted code. 6 is the universal default — Google
 *   Authenticator, Microsoft Authenticator, Yubico, and every other
 *   mainstream app agree on 6. Twilio Authy accepts 7. Aegis / 2FAS /
 *   FreeOTP / 1Password / Bitwarden accept 6-10. Values above 10
 *   would emit non-uniform digits and are refused.
 * @property {OtpAlgorithm} [algorithm='SHA1']
 *   HMAC algorithm. **`SHA1` is the only value that works everywhere** —
 *   Google Authenticator and Microsoft Authenticator only accept SHA-1.
 *   `SHA256` and `SHA512` are supported by Twilio Authy (SHA-256 only),
 *   Aegis, 2FAS, FreeOTP, 1Password, Bitwarden, and Yubico
 *   Authenticator. Stick with SHA-1 for public-facing enrollment;
 *   SHA-256/512 only when you control the client too.
 */

/**
 * @typedef {object} HotpVerifyOptions
 * @property {6 | 7 | 8 | 9 | 10} [digits=6]
 * @property {OtpAlgorithm} [algorithm='SHA1']
 * @property {number} [window=1]
 *   Counter drift tolerance — accept codes in the range
 *   `[counter, counter + window]`. HOTP always looks *ahead* (never
 *   behind) because used counters can never be replayed. Set to 0 for
 *   strict single-counter verify.
 */

function assertCounter(counter) {
  if (!Number.isInteger(counter) || counter < 0) {
    throw new OtpError(ErrorCode.INVALID_ARGUMENT, `HOTP counter must be a non-negative integer; got ${counter}`);
  }
  // JavaScript's max safe integer covers ~2^53 — well beyond any realistic
  // HOTP counter. If someone bumps a counter past this they have bigger
  // problems, but we refuse to overflow silently.
  if (counter > Number.MAX_SAFE_INTEGER) {
    throw new OtpError(ErrorCode.INVALID_ARGUMENT, 'HOTP counter exceeds Number.MAX_SAFE_INTEGER');
  }
}

function assertAlgorithm(algorithm) {
  if (!SUPPORTED_ALGORITHMS.has(algorithm)) {
    throw new OtpError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `algorithm must be one of ${[...SUPPORTED_ALGORITHMS].join(', ')}; got '${algorithm}'`,
    );
  }
}

function assertDigits(digits) {
  // RFC 4226 mandates a minimum of 6; the upper bound is dictated by the
  // 31-bit dynamic-truncation output (2^31 = 2,147,483,648). Codes with
  // 10 digits are the widest useful width — Bitwarden / 1Password accept
  // them. Values above 10 would emit non-uniform digits (leading digit
  // always 0/1) and we refuse rather than produce a subtly biased code.
  if (!Number.isInteger(digits) || digits < 6 || digits > 10) {
    throw new OtpError(ErrorCode.INVALID_ARGUMENT, `digits must be an integer in [6, 10]; got ${digits}`);
  }
}

// The HOTP core spec (RFC 4226 §5.1): counter is a 64-bit big-endian
// integer. JavaScript numbers cover 53 bits safely, which is more than
// enough for time-based counters but we still write the full 8 bytes.
function counterToBuffer(counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter), 0);
  return buf;
}

/**
 * RFC 4226 HOTP — HMAC-based one-time password.
 *
 * @param {string | Buffer | Uint8Array} secret
 * @param {number} counter
 * @param {HotpOptions} [options]
 * @returns {string}                Zero-padded N-digit code.
 */
export function hotp(secret, counter, options = {}) {
  const digits = options.digits ?? 6;
  const algorithm = options.algorithm ?? 'SHA1';
  assertDigits(digits);
  assertAlgorithm(algorithm);
  assertCounter(counter);

  const key = decodeSecret(secret);
  const mac = createHmac(algorithm.toLowerCase(), key).update(counterToBuffer(counter)).digest();
  return truncate(mac, digits);
}

/**
 * Verify a counter-based OTP, returning the *matched counter* on
 * success (so the caller can advance their stored value) or `null`
 * when nothing in the drift window matched.
 *
 * The compare is timing-safe. Every candidate counter in the window
 * is checked even after a match — the constant-time property does
 * not extend across the loop, but the input is derived from a
 * pre-computed hash, not the user's guess, so this is safe.
 *
 * @param {unknown} code    User-supplied candidate (string of digits).
 * @param {string | Buffer | Uint8Array} secret
 * @param {number} counter  Current stored counter.
 * @param {HotpVerifyOptions} [options]
 * @returns {number | null} Matched counter (advance to `matched + 1`)
 *                          or `null` on no match.
 */
export function verifyHotp(code, secret, counter, options = {}) {
  if (typeof code !== 'string' || code.length === 0) {
    return null;
  }
  const digits = options.digits ?? 6;
  const algorithm = options.algorithm ?? 'SHA1';
  const window = options.window ?? 1;
  assertDigits(digits);
  assertAlgorithm(algorithm);
  assertCounter(counter);
  if (!Number.isInteger(window) || window < 0 || window > 10) {
    throw new OtpError(ErrorCode.INVALID_ARGUMENT, `HOTP window must be an integer in [0, 10]; got ${window}`);
  }

  // Reject obviously wrong shapes upfront — but do NOT skip the loop
  // when the shape matches so timing doesn't leak "known length".
  if (code.length !== digits || !/^\d+$/.test(code)) {
    return null;
  }

  const target = Buffer.from(code, 'utf8');
  let matched = null;
  for (let i = 0; i <= window; i++) {
    const candidate = Buffer.from(hotp(secret, counter + i, { digits, algorithm }), 'utf8');
    if (timingSafeEqual(target, candidate) && matched === null) {
      matched = counter + i;
    }
  }
  return matched;
}

/**
 * @typedef {object} ResyncOptions
 * @property {number} [startCounter=0]
 *   Where to start scanning. Almost always the last known-good counter
 *   from your database.
 * @property {number} [maxLookAhead=500]
 *   How far ahead of `startCounter` we scan. RFC 4226 §7.4 does not
 *   specify a bound; production deployments use 100–1000 depending on
 *   how often tokens might drift.
 * @property {6 | 7 | 8 | 9 | 10} [digits=6]
 * @property {OtpAlgorithm} [algorithm='SHA1']
 */

/**
 * RFC 4226 §7.4 counter resynchronisation. Given two consecutive OTPs
 * the user typed off a hardware token that drifted, find the counter
 * value that makes both codes match — code #1 at some counter `N`
 * and code #2 at exactly `N+1`. Returns the *next* counter to store
 * (`N + 2`) on success, or `null` when the pair is not consistent.
 *
 * The scan is bounded by `maxLookAhead`; requests further off than
 * that fail rather than hanging.
 *
 *   const nextCounter = resynchronize(secret, ['847362', '128394'], {
 *     startCounter: userRow.hotpCounter,
 *   })
 *   if (nextCounter === null) return res.status(400).end('resync failed')
 *   await db.users.update(userId, { hotpCounter: nextCounter })
 *
 * @param {string | Buffer | Uint8Array} secret
 * @param {[string, string]} codes                Two consecutive user-entered codes.
 * @param {ResyncOptions} [options]
 * @returns {number | null}
 */
export function resynchronize(secret, codes, options = {}) {
  if (!Array.isArray(codes) || codes.length !== 2) {
    throw new OtpError(
      ErrorCode.INVALID_ARGUMENT,
      'resynchronize: codes must be an array of exactly two consecutive OTPs',
    );
  }
  const [code1, code2] = codes;
  if (typeof code1 !== 'string' || typeof code2 !== 'string') {
    return null;
  }
  const digits = options.digits ?? 6;
  const algorithm = options.algorithm ?? 'SHA1';
  const startCounter = options.startCounter ?? 0;
  const maxLookAhead = options.maxLookAhead ?? 500;
  assertDigits(digits);
  assertAlgorithm(algorithm);
  assertCounter(startCounter);
  if (!Number.isInteger(maxLookAhead) || maxLookAhead < 1 || maxLookAhead > 10_000) {
    throw new OtpError(
      ErrorCode.INVALID_ARGUMENT,
      `resynchronize: maxLookAhead must be an integer in [1, 10000]; got ${maxLookAhead}`,
    );
  }

  // Scan forward looking for a counter N where hotp(N) === code1 AND
  // hotp(N+1) === code2. This is O(maxLookAhead) HMACs, cheap.
  const t1 = Buffer.from(code1, 'utf8');
  const t2 = Buffer.from(code2, 'utf8');
  for (let i = 0; i <= maxLookAhead; i++) {
    const c1 = Buffer.from(hotp(secret, startCounter + i, { digits, algorithm }), 'utf8');
    if (c1.length !== t1.length || !timingSafeEqual(t1, c1)) {
      continue;
    }
    const c2 = Buffer.from(hotp(secret, startCounter + i + 1, { digits, algorithm }), 'utf8');
    if (c2.length === t2.length && timingSafeEqual(t2, c2)) {
      return startCounter + i + 2;
    }
  }
  return null;
}
