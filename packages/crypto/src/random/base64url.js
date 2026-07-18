import { bytes } from './bytes.js';
import { assertNonNegativeInt } from '@exortek/shared/asserts';

/**
 * URL-safe base64 random string (RFC 4648 §5), no padding.
 *
 * Generates `size` random bytes and returns them base64url-encoded:
 * uses `-` and `_` instead of `+` / `/`, and strips trailing `=` padding.
 * Safe to embed in URLs, JWTs, cookies and HTTP headers without further encoding.
 *
 * Validation is delegated to {@link bytes} — invalid `size` values raise the
 * same `CryptoError(INVALID_ARGUMENT)`.
 *
 * @param {number} size  Number of random bytes to produce. Must be a non-negative integer.
 * @returns {string}     URL-safe base64 string, no `=` padding.
 * @throws {CryptoError} With code `INVALID_ARGUMENT` (propagated from {@link bytes}).
 *
 * @example
 * base64url(32) // 'rJ9aQ2x-K7vN_pL...' — 43 chars, URL-safe, no '=' padding
 */
export function base64url(size) {
  assertNonNegativeInt(size, 'base64url size');
  return bytes(size).toString('base64url');
}
