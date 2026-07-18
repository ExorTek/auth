import * as sb32 from '@exortek/shared/base32';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertOptionalObject, assertString } from '../internal/validate.js';
import { toBuffer } from '../internal/bytes.js';

/** Accepts uppercase, lowercase, and optional `=` padding. */
const BASE32_RE = /^[A-Za-z2-7]*={0,6}$/;

/**
 * @typedef {object} Base32EncodeOptions
 * @property {boolean} [padding=false]  Append `=` to align output length to a
 *                                       multiple of 8 chars. RFC-compliant but
 *                                       not required — TOTP secret sharing
 *                                       omits padding by convention.
 */

/**
 * Encode `input` as an RFC 4648 §6 Base32 string (uppercase, no padding).
 *
 * Base32 is the interop format for TOTP / HOTP secret sharing (Google
 * Authenticator, Authy) — MFA setup QR codes carry the shared secret in
 * this exact encoding. Also common in DNS TXT record encodings.
 *
 * Prefer {@link base64url} for URL-safe binary transport and
 * {@link hex} for debugging — Base32 is denser than hex but sparser
 * than base64, chosen mostly for its human-typable alphabet.
 *
 * @param {string | Buffer | Uint8Array} input
 * @param {Base32EncodeOptions}          [options]
 * @returns {string}                     Uppercase Base32 string.
 * @throws {CryptoError}                 With code `INVALID_ARGUMENT` if `input`
 *                                       is neither a string nor a Buffer/Uint8Array.
 *
 * @example
 * encode('Hello')                       // 'JBSWY3DPEE'
 * encode('Hello', { padding: true })    // 'JBSWY3DPEE======'
 * encode(Buffer.from([0xff, 0x00]))     // '74AA'
 */
export function encode(input, options) {
  assertOptionalObject(options, 'options');
  const padding = options?.padding ?? false;
  const buf = toBuffer(input, 'input');
  return sb32.encode(buf, { padding });
}

/**
 * Decode a Base32 string into a Buffer.
 *
 * Accepts uppercase, lowercase and mixed-case input; `=` padding is
 * optional (both TOTP-style unpadded and RFC-strict padded forms work).
 *
 * @param {string} input
 * @returns {Buffer}
 * @throws {CryptoError}   With code `INVALID_ARGUMENT` if `input` is not a
 *                         string, or `INVALID_ENCODING` if it contains
 *                         characters outside the Base32 alphabet.
 *
 * @example
 * decode('JBSWY3DPEE')       // Buffer('Hello')
 * decode('JBSWY3DPEE======') // Buffer('Hello') — padding tolerated
 * decode('jbswy3dpee')       // Buffer('Hello') — case-insensitive
 */
export function decode(input) {
  assertString(input, 'input');
  if (!BASE32_RE.test(input)) {
    throw new CryptoError(
      ErrorCode.INVALID_ENCODING,
      'input is not a valid Base32 string — allowed chars: A-Z (case-insensitive) and 2-7 with optional trailing = padding. RFC 4648 §6.',
    );
  }
  return sb32.decode(input);
}
