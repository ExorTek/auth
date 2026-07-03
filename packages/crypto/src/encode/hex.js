import { CryptoError, ErrorCode } from '../errors.js';
import { assertString } from '../internal/validate.js';
import { toBuffer } from '../internal/bytes.js';

/** Hex digits, case-insensitive. Length must be even (each byte = 2 chars). */
const HEX_RE = /^([0-9a-fA-F]{2})*$/;

/**
 * Encode `input` as a lowercase hex string.
 *
 * Strings are interpreted as UTF-8. Buffers are encoded byte-by-byte.
 *
 * @param {string | Buffer | Uint8Array} input
 * @returns {string}       Lowercase hex string, length = `input` byte length × 2.
 * @throws {CryptoError}   With code `INVALID_ARGUMENT` if `input` is neither a string
 *                         nor a Buffer/Uint8Array.
 *
 * @example
 * encode('hello')                              // '68656c6c6f'
 * encode(Buffer.from([0xde, 0xad, 0xbe, 0xef]))  // 'deadbeef'
 */
export function encode(input) {
  return toBuffer(input, 'input').toString('hex');
}

/**
 * Decode a hex string into a Buffer.
 *
 * Accepts uppercase, lowercase and mixed-case hex. Length must be even.
 *
 * @param {string} input
 * @returns {Buffer}
 * @throws {CryptoError}   With code `INVALID_ARGUMENT` if `input` is not a string,
 *                         or `INVALID_ENCODING` if it is malformed (odd length or
 *                         non-hex chars).
 *
 * @example
 * decode('68656c6c6f')    // Buffer('hello')
 * decode('DEADBEEF')      // Buffer([0xde, 0xad, 0xbe, 0xef])
 */
export function decode(input) {
  assertString(input, 'input');
  if (!HEX_RE.test(input)) {
    throw new CryptoError(ErrorCode.INVALID_ENCODING, 'input is not a valid hex string (even length, hex chars only)');
  }
  return Buffer.from(input, 'hex');
}
