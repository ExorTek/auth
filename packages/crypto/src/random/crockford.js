import { bytes } from './bytes.js';
import { CROCKFORD } from '../internal/alphabets.js';
import { assertNonNegativeInt } from '@exortek/shared/asserts';

/**
 * Crockford base32 random string (ULID-style).
 *
 * Generates `size` random bytes and encodes them in Crockford base32 — a
 * 32-character alphabet that deliberately omits `I`, `L`, `O`, `U` to
 * avoid look-alike confusion and accidental profanity. The output is
 * URL-safe, case-insensitive on read, and lexicographically sortable
 * when concatenated with a fixed-length timestamp prefix.
 *
 * Output length is `ceil(size * 8 / 5)` characters: 16 bytes → 26 chars,
 * 10 bytes → 16 chars (the same 80-bit tail ULID uses).
 *
 * @param {number} size  Number of random bytes of entropy. Must be a non-negative integer.
 * @returns {string}     Uppercase Crockford base32 string.
 * @throws {CryptoError} With code `INVALID_ARGUMENT` (propagated from {@link bytes}).
 *
 * @example
 * crockford(10)  // '01ARZ3NDEKTSV4RR' — 16 chars, 80 bits of entropy
 * crockford(16)  // 26-char string, 128 bits of entropy
 */
export function crockford(size) {
  assertNonNegativeInt(size, 'crockford size');
  const buf = bytes(size);
  const outLen = Math.ceil((buf.length * 8) / 5);
  let n = 0n;
  for (let i = 0; i < buf.length; i++) {
    n = (n << 8n) | BigInt(buf[i]);
  }
  let out = '';
  for (let i = 0; i < outLen; i++) {
    out = CROCKFORD[Number(n & 0x1fn)] + out;
    n >>= 5n;
  }
  return out;
}
