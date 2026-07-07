import { CryptoError, ErrorCode } from '../errors.js';
import { assertOptionalObject, assertString } from '../internal/validate.js';
import { toBuffer } from '../internal/bytes.js';

/** RFC 4648 §6 Base32 alphabet — 32 chars, uppercase, no look-alike stripping. */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Reverse lookup: char → 5-bit value. Filled once at module load. */
const DECODE_TABLE = new Int8Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) {
  DECODE_TABLE[ALPHABET.charCodeAt(i)] = i;
  // Case-insensitive decode for letters only — digits (`2`-`7`) at code points
  // 50-55 add to letter code points via `+32`, which would corrupt the letter
  // lookup entries. Skip the alias for the digit rows.
  if (i < 26) {
    DECODE_TABLE[ALPHABET.charCodeAt(i) + 32] = i;
  }
}

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
  if (buf.length === 0) {
    return '';
  }

  // Keep `value` at ≤ 12 bits by masking after each emit — JS bitwise ops are
  // 32-bit signed, so accumulating 40+ bits into `value` would silently drop
  // the high bytes.
  let out = '';
  let bits = 0;
  let value = 0;
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(value >>> bits) & 0x1f];
      value &= (1 << bits) - 1;
    }
  }
  if (bits > 0) {
    out += ALPHABET[(value << (5 - bits)) & 0x1f];
  }

  if (padding) {
    while (out.length % 8 !== 0) {
      out += '=';
    }
  }
  return out;
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
  // Strip padding for the bit-unpacking pass.
  const stripped = input.replace(/=+$/, '');
  if (stripped.length === 0) {
    return Buffer.alloc(0);
  }

  // Each 5 chars encode 5 bytes; final group may carry 1..4 partial bytes.
  const outLength = Math.floor((stripped.length * 5) / 8);
  const out = Buffer.alloc(outLength);
  // Mask `value` down after each byte emit for the same 32-bit reason as encode.
  let bits = 0;
  let value = 0;
  let index = 0;
  for (let i = 0; i < stripped.length; i++) {
    value = (value << 5) | DECODE_TABLE[stripped.charCodeAt(i)];
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (value >>> bits) & 0xff;
      value &= (1 << bits) - 1;
    }
  }
  return out;
}
