import { assertPositiveInt } from '../internal/validate.js';
import { biasFreeSample } from '../internal/sample.js';

const ALPHABET = '0123456789';

/**
 * Bias-free numeric random string.
 *
 * Samples uniformly from `[0-9]` using rejection sampling — no modulo bias.
 * Ideal for OTP codes, PINs and verification numbers. Leading zeros are
 * preserved (output is always a string, never a number).
 *
 * @param {number} length  Desired output length. Must be a positive integer.
 * @returns {string}       Random string of exactly `length` digits.
 * @throws {CryptoError}   With code `INVALID_ARGUMENT` if `length` is not a positive integer.
 *
 * @example
 * numeric(6)  // '847291' — a 6-digit OTP
 * numeric(4)  // '0413'   — leading zero preserved
 */
export function numeric(length) {
  assertPositiveInt(length, 'length');
  return biasFreeSample(ALPHABET, length);
}
