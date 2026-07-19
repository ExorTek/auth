import { bytes } from './bytes.js';
import { assertNonNegativeInt } from '../internal/guards.js';

/**
 * Hex-encoded random string.
 *
 * Generates `size` random bytes and returns them as a lowercase hex string of
 * length `size * 2`. Validation is delegated to {@link bytes} — invalid `size`
 * values raise the same `CryptoError(INVALID_ARGUMENT)`.
 *
 * @param {number} size  Number of random bytes to produce. Must be a non-negative integer.
 * @returns {string}     Lowercase hex string of length `size * 2`.
 * @throws {CryptoError} With code `INVALID_ARGUMENT` (propagated from {@link bytes}).
 *
 * @example
 * hex(16) // 'a3f9b2c1...' — 32-char hex, e.g. a session id or CSRF token
 */
export function hex(size) {
  assertNonNegativeInt(size, 'bytes size');
  return bytes(size).toString('hex');
}
