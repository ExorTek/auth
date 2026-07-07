import { CryptoError, ErrorCode } from '../errors.js';
import { assertString } from '../internal/validate.js';
import { toBuffer } from '../internal/bytes.js';
import { CROCKFORD } from '../internal/alphabets.js';

/** Reverse lookup: char code → 5-bit value. Filled once at module load. */
const DECODE_TABLE = new Int8Array(128).fill(-1);
for (let i = 0; i < CROCKFORD.length; i++) {
  DECODE_TABLE[CROCKFORD.charCodeAt(i)] = i;
  // Lowercase alias for letters only. Digits (`0`-`9`) share code point
  // rows that would collide with the +32 shift used for uppercase letters.
  const c = CROCKFORD[i];
  if (c >= 'A' && c <= 'Z') {
    DECODE_TABLE[CROCKFORD.charCodeAt(i) + 32] = i;
  }
}
// Crockford check aliases: I/L → 1, O → 0 (case-insensitive).
for (const [alias, canonical] of [
  ['I', '1'],
  ['i', '1'],
  ['L', '1'],
  ['l', '1'],
  ['O', '0'],
  ['o', '0'],
]) {
  DECODE_TABLE[alias.charCodeAt(0)] = DECODE_TABLE[canonical.charCodeAt(0)];
}

/**
 * Encode `input` as a Crockford base32 string (ULID-style).
 *
 * Crockford's alphabet (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`) drops the four
 * look-alike glyphs `I`, `L`, `O`, `U` — the first two are ambiguous with
 * `1`, the third with `0`, the last was removed to prevent accidental
 * profanity. Case-insensitive on decode, URL-safe on the wire, and
 * lexicographically sortable when prefixed with a fixed-width timestamp
 * (the design ULID borrows).
 *
 * @param {string | Buffer | Uint8Array} input
 * @returns {string}                     Uppercase Crockford base32 string.
 * @throws {CryptoError}                 `INVALID_ARGUMENT` if `input` is neither
 *                                        a string nor a Buffer/Uint8Array.
 *
 * @example
 * encode(Buffer.from([0x00, 0xff]))   // '007Z'
 * encode('Hello')                      // '91JPRV3F'
 */
export function encode(input) {
  const buf = toBuffer(input, 'input');
  if (buf.length === 0) {
    return '';
  }

  let out = '';
  let bits = 0;
  let value = 0;
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += CROCKFORD[(value >>> bits) & 0x1f];
      value &= (1 << bits) - 1;
    }
  }
  if (bits > 0) {
    out += CROCKFORD[(value << (5 - bits)) & 0x1f];
  }
  return out;
}

/**
 * Decode a Crockford base32 string into a Buffer.
 *
 * Case-insensitive. Accepts the Crockford check aliases: `I`/`L` are read
 * as `1`, `O` as `0`. The four uppercase check symbols (`*`, `~`, `$`,
 * `=`, `U`) that some tools append are **not** supported — decode fails.
 *
 * @param {string} input
 * @returns {Buffer}
 * @throws {CryptoError} `INVALID_ARGUMENT` if `input` is not a string;
 *                       `INVALID_ENCODING` for any character outside the
 *                       Crockford alphabet.
 *
 * @example
 * decode('91JPRV3F')   // Buffer('Hello')
 * decode('91jprv3f')   // Buffer('Hello') — case-insensitive
 */
export function decode(input) {
  assertString(input, 'input');
  if (input.length === 0) {
    return Buffer.alloc(0);
  }
  const outLength = Math.floor((input.length * 5) / 8);
  const out = Buffer.alloc(outLength);
  let bits = 0;
  let value = 0;
  let index = 0;
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    const v = code < 128 ? DECODE_TABLE[code] : -1;
    if (v === -1) {
      throw new CryptoError(
        ErrorCode.INVALID_ENCODING,
        `input contains a non-Crockford character '${input[i]}' at index ${i}`,
      );
    }
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (value >>> bits) & 0xff;
      value &= (1 << bits) - 1;
    }
  }
  return out;
}
