import crypto from 'node:crypto';
import { assertNonNegativeInt } from '../internal/validate.js';

/**
 * Cryptographically secure random byte sequence.
 *
 * Backed by the OS CSPRNG via `crypto.randomBytes`. Suitable for keys, IVs,
 * tokens and any other security-sensitive randomness. Never use `Math.random()`
 * for these purposes.
 *
 * @param {number} size  Number of random bytes to produce. Must be a non-negative integer.
 * @returns {Buffer}     Buffer of length `size` filled with random bytes.
 * @throws {CryptoError} With code `INVALID_ARGUMENT` if `size` is not a non-negative integer.
 *
 * @example
 * const key = bytes(32) // 256-bit random key
 */
export function bytes(size) {
  assertNonNegativeInt(size, 'size');
  return crypto.randomBytes(size);
}
