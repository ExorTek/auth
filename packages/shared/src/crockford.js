/**
 * Crockford Base32 codec — RFC 4648-style but with the four look-alike
 * glyphs `I`, `L`, `O`, `U` dropped for human legibility. Uppercase on
 * encode, case-insensitive on decode with Crockford check aliases:
 * `I` / `L` decode as `1`, `O` decodes as `0`. The four uppercase check
 * symbols (`*`, `~`, `$`, `=`) that some tooling appends are **not**
 * supported.
 *
 * Consumers (crypto public codec, otp backup codes, jwt polymorphic
 * encoding) all reach for the same alphabet + encode loop; this file
 * is the single implementation. Errors here are plain `Error` /
 * `TypeError`; each consumer wraps them into its own typed error at
 * the surface boundary.
 */

export const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

const DECODE_TABLE = new Int8Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) {
  DECODE_TABLE[ALPHABET.charCodeAt(i)] = i;
  const c = ALPHABET[i];
  if (c >= 'A' && c <= 'Z') {
    // Lowercase alias for letters only. Digits share code point rows
    // that would collide with the +32 shift used for uppercase.
    DECODE_TABLE[ALPHABET.charCodeAt(i) + 32] = i;
  }
}
// Crockford check aliases: I / L → 1, O → 0 (case-insensitive).
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
 * Encode bytes as a Crockford base32 string.
 *
 * @param {Buffer | Uint8Array} bytes
 * @returns {string}
 * @throws {TypeError} if `bytes` is not a Buffer or Uint8Array.
 */
export function encode(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('encode: input must be a Buffer or Uint8Array.');
  }
  if (bytes.length === 0) {
    return '';
  }

  let out = '';
  let bits = 0;
  let value = 0;
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
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
  return out;
}

/**
 * Decode a Crockford base32 string into a Buffer.
 *
 * Case-insensitive. `I` / `L` → `1`, `O` → `0`. Any other non-alphabet
 * character throws.
 *
 * @param {string} input
 * @returns {Buffer}
 * @throws {TypeError} if `input` is not a string.
 * @throws {Error}     if `input` contains a character outside the alphabet.
 */
export function decode(input) {
  if (typeof input !== 'string') {
    throw new TypeError('decode: input must be a string.');
  }
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
      throw new Error(
        `input contains a non-Crockford character '${input[i]}' at index ${i}. Crockford base32 alphabet is 0-9 A-Z minus I L O U (case-insensitive); I/L decode as 1, O decodes as 0.`,
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
