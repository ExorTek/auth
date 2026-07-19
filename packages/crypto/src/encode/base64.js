import { CryptoError, ErrorCode } from '../errors.js';
import { assertNonNegativeInt, assertString } from '../internal/guards.js';
import { toBuffer } from '../internal/bytes.js';
import crypto from 'node:crypto';

/** Standard base64 alphabet (RFC 4648 §4), with optional `=` padding to a multiple of 4. */
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * Encode `input` as standard base64 (RFC 4648 §4), including `=` padding.
 *
 * Strings are interpreted as UTF-8. For URL-safe output (no `+`, `/`, `=`)
 * use {@link base64url.encode} instead — that is the preferred form for
 * JWTs, cookies and HTTP headers.
 *
 * @param {string | Buffer | Uint8Array} input
 * @returns {string}       Standard base64 string, padded to a multiple of 4.
 * @throws {CryptoError}   With code `INVALID_ARGUMENT` if `input` is neither a string
 *                         nor a Buffer/Uint8Array.
 *
 * @example
 * encode('hello')                              // 'aGVsbG8='
 * encode(Buffer.from([0xff, 0x00, 0xff]))      // '/wD/'
 */
export function encode(input) {
  return toBuffer(input, 'input').toString('base64');
}

/**
 * Decode a standard base64 string into a Buffer.
 *
 * Accepts padded and unpadded forms.
 *
 * @param {string} input
 * @returns {Buffer}
 * @throws {CryptoError}   With code `INVALID_ARGUMENT` if `input` is not a string,
 *                         or `INVALID_ENCODING` if it contains non-base64 chars.
 *
 * @example
 * decode('aGVsbG8=')      // Buffer('hello')
 * decode('aGVsbG8')       // Buffer('hello') — padding optional
 */
export function decode(input) {
  assertString(input, 'input');
  if (!BASE64_RE.test(input)) {
    throw new CryptoError(
      ErrorCode.INVALID_ENCODING,
      'input is not a valid base64 string — allowed chars: A-Z a-z 0-9 + / and trailing = padding. For URL contexts use base64url.decode (- and _ instead of + and /).',
    );
  }
  return Buffer.from(input, 'base64');
}

export function randomBase64(size) {
  assertNonNegativeInt(size, 'size');
  return crypto.randomBytes(size).toString('base64');
}
