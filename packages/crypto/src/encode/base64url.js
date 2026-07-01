import { CryptoError, ErrorCode } from '../errors.js';
import { assertString } from '../internal/validate.js';

/** Canonical base64url alphabet (RFC 4648 §5), with or without `=` padding. */
const BASE64URL_RE = /^[A-Za-z0-9_-]*={0,2}$/;

/**
 * Encode `input` as base64url (RFC 4648 §5): URL-safe alphabet, no `=` padding.
 *
 * Strings are interpreted as UTF-8. Buffers are encoded directly.
 *
 * @param {string | Buffer | Uint8Array} input
 * @returns {string}       URL-safe base64 string with no `=` padding.
 * @throws {CryptoError}   With code `INVALID_ARGUMENT` if `input` is neither a string
 *                         nor a Buffer/Uint8Array.
 *
 * @example
 * encode('hello')                              // 'aGVsbG8'
 * encode(Buffer.from([0xff, 0x00, 0xff]))      // '_wD_'
 */
export function encode(input) {
  if (typeof input === 'string') {
    return Buffer.from(input, 'utf8').toString('base64url');
  }
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    return Buffer.from(input.buffer, input.byteOffset, input.byteLength).toString('base64url');
  }
  throw new CryptoError(ErrorCode.INVALID_ARGUMENT, 'input must be a string or Buffer');
}

/**
 * Decode a base64url string into a Buffer.
 *
 * Accepts both padded (`=`) and unpadded forms; `+` / `/` are not allowed
 * (use {@link base64.decode} for standard base64).
 *
 * @param {string} input
 * @returns {Buffer}
 * @throws {CryptoError}   With code `INVALID_ARGUMENT` if `input` is not a string,
 *                         or `INVALID_ENCODING` if it contains non-base64url chars.
 *
 * @example
 * decode('aGVsbG8')     // Buffer('hello')
 * decode('_wD_')        // Buffer([0xff, 0x00, 0xff])
 */
export function decode(input) {
  assertString(input, 'input');
  if (!BASE64URL_RE.test(input)) {
    throw new CryptoError(ErrorCode.INVALID_ENCODING, 'input is not a valid base64url string');
  }
  return Buffer.from(input, 'base64url');
}
