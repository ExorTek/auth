import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertBytesOrString, assertOptionalObject, assertString } from '../internal/validate.js';

/**
 * @typedef {object} SignedValueOptions
 * @property {'sha256' | 'sha384' | 'sha512'} [algo='sha256']
 *   HMAC hash. `sha256` is the sensible default; `sha512` gives a longer MAC
 *   at negligible speed cost on 64-bit CPUs.
 */

const _SUPPORTED = new Set(['sha256', 'sha384', 'sha512']);
const SEPARATOR = '.';

/**
 * Sign an opaque string value with a secret, producing a self-verifying string
 * you can safely round-trip through a cookie, header, URL fragment, or link.
 *
 * This is the primitive behind Express's `cookie-signature`, Django's
 * `signing`, and Rails's `MessageVerifier` — HMAC over the raw value, encoded
 * and appended after a separator. Never write it yourself.
 *
 * **Not encryption.** The value is visible in the output; a signed cookie
 * proves the client hasn't tampered with it, not that they can't read it.
 * Use {@link seal} when confidentiality is required.
 *
 * The output is `"<value>.<base64url_hmac>"`. Because `.` is the separator,
 * `value` **must not contain** a `.` character — sign a base64url or hex-
 * encoded form if you need arbitrary bytes.
 *
 * @param {string}                       value    Opaque payload. Must be a
 *                                                dot-free string.
 * @param {string | Buffer | Uint8Array} secret   Shared HMAC key. Rotate by
 *                                                trying each candidate secret
 *                                                on `unsignValue`.
 * @param {SignedValueOptions}           [options]
 * @returns {string}                      `<value>.<mac>`
 * @throws {CryptoError} With code:
 *   - `INVALID_ARGUMENT` if `value` is not a string or contains `.`
 *   - `UNSUPPORTED_ALGORITHM` if `options.algo` is not one of sha256/384/512
 *
 * @example
 * // Session cookie value
 * const cookie = signValue('sid:8f2a', process.env.COOKIE_SECRET)
 * // → 'sid:8f2a.eyJhbGci...'
 *
 * @example
 * // Rotating secrets — sign with the newest, verify with any
 * const signed = signValue('user:42', SECRETS[0])
 * const orig   = SECRETS.map(s => unsignValue(signed, s)).find(Boolean)
 */
export function signValue(value, secret, options) {
  assertString(value, 'value');
  assertBytesOrString(secret, 'secret');
  assertOptionalObject(options, 'options');
  if (value.includes(SEPARATOR)) {
    throw new CryptoError(ErrorCode.INVALID_ARGUMENT, "value must not contain '.'; encode as base64url or hex first");
  }
  const algo = options?.algo ?? 'sha256';
  if (!_SUPPORTED.has(algo)) {
    throw new CryptoError(ErrorCode.UNSUPPORTED_ALGORITHM, 'algo must be one of: sha256, sha384, sha512');
  }
  const mac = crypto.createHmac(algo, secret).update(value).digest('base64url');
  return `${value}${SEPARATOR}${mac}`;
}

/**
 * Verify and unwrap a value produced by {@link signValue}.
 *
 * Returns the original value on success, or `null` on any failure — malformed
 * input, wrong secret, wrong algorithm. The comparison is timing-safe.
 *
 * `null` is the return path used by `cookie-signature`, Django, and Rails —
 * this is a boundary check, not a program-error condition. Match on `null`,
 * don't try/catch.
 *
 * @param {string}                       signed   Output of {@link signValue}.
 * @param {string | Buffer | Uint8Array} secret   Same HMAC key used to sign.
 * @param {SignedValueOptions}           [options]  Must match the sign-time algo.
 * @returns {string | null}
 *
 * @example
 * const value = unsignValue(cookie, process.env.COOKIE_SECRET)
 * if (value === null) return res.status(401).end()
 */
export function unsignValue(signed, secret, options) {
  assertString(signed, 'signed');
  assertBytesOrString(secret, 'secret');
  assertOptionalObject(options, 'options');
  const algo = options?.algo ?? 'sha256';
  if (!_SUPPORTED.has(algo)) {
    return null;
  }
  const i = signed.lastIndexOf(SEPARATOR);
  if (i <= 0 || i === signed.length - 1) {
    return null;
  }
  const value = signed.slice(0, i);
  const provided = signed.slice(i + 1);
  const expected = crypto.createHmac(algo, secret).update(value).digest('base64url');
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  if (a.length !== b.length) {
    return null;
  }
  return crypto.timingSafeEqual(a, b) ? value : null;
}
