import { bytes } from './bytes.js';
import { BASE58 } from '../internal/alphabets.js';

/**
 * Bitcoin base58 random string.
 *
 * Generates `size` random bytes and encodes them with the 58-character
 * Bitcoin alphabet (omits `0`, `O`, `I`, `l` for readability). Leading
 * zero bytes in the input are preserved as leading `'1'` characters in
 * the output, matching Base58Check semantics used by Bitcoin addresses.
 *
 * Output length is variable — roughly `size * 1.365` characters — because
 * 58 is not a power of two.
 *
 * @param {number} size  Number of random bytes of entropy. Must be a non-negative integer.
 * @returns {string}     Base58 string.
 * @throws {CryptoError} With code `INVALID_ARGUMENT` (propagated from {@link bytes}).
 *
 * @example
 * base58(16)  // 'V1StGXR8Z5jdHi6BmyT' — 128 bits of entropy, ~22 chars
 */
export function base58(size) {
  const buf = bytes(size);
  if (buf.length === 0) {
    return '';
  }

  let n = 0n;
  for (let i = 0; i < buf.length; i++) {
    n = (n << 8n) | BigInt(buf[i]);
  }

  let out = '';
  while (n > 0n) {
    out = BASE58[Number(n % 58n)] + out;
    n /= 58n;
  }
  // Preserve leading zero bytes as leading '1' characters (Base58Check convention).
  for (let i = 0; i < buf.length && buf[i] === 0; i++) {
    out = '1' + out;
  }
  return out;
}
