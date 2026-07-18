import { bytes } from './bytes.js';
import { assertNonNegativeInt } from '@exortek/shared/asserts';

/**
 * Standard base64 random string (RFC 4648 §4), with `=` padding.
 *
 * Generates `size` random bytes and returns them base64-encoded with the
 * standard alphabet (`+`, `/`, `=`). Prefer {@link base64url} for anything
 * URL / cookie / JWT-adjacent — this variant exists for legacy interop.
 *
 * Validation is delegated to {@link bytes} — invalid `size` values raise the
 * same `CryptoError(INVALID_ARGUMENT)`.
 *
 * @param {number} size  Number of random bytes to produce. Must be a non-negative integer.
 * @returns {string}     Standard base64 string, padded to a multiple of 4.
 * @throws {CryptoError} With code `INVALID_ARGUMENT` (propagated from {@link bytes}).
 *
 * @example
 * base64(16) // 'V1StGXR8Z5jdHi6BmyT=' — 24 chars, includes '=' padding
 */
export function base64(size) {
  assertNonNegativeInt(size, 'base64 size');
  return bytes(size).toString('base64');
}
