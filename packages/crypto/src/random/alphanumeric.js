import { assertPositiveInt } from '@exortek/shared/asserts';
import { biasFreeSample } from '../internal/sample.js';
import { ALPHANUM } from '../internal/alphabets.js';

/**
 * Bias-free alphanumeric random string.
 *
 * Samples uniformly from `[A-Za-z0-9]` (62 characters) using rejection
 * sampling — no modulo bias. Nanoid-style identifiers: URL-safe,
 * human-copyable, no separators.
 *
 * @param {number} length  Desired output length. Must be a positive integer.
 * @returns {string}       Random string of exactly `length` characters from `[A-Za-z0-9]`.
 * @throws {CryptoError}   With code `INVALID_ARGUMENT` if `length` is not a positive integer.
 *
 * @example
 * alphanumeric(21) // 'V1StGXR8Z5jdHi6BmyTQ' — nanoid-style ID (~126 bits of entropy)
 */
export function alphanumeric(length) {
  assertPositiveInt(length, 'alphanumeric length');
  return biasFreeSample(ALPHANUM, length);
}
