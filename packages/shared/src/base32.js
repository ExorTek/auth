/**
 * RFC 4648 §6 Base32 codec (uppercase A-Z 2-7 alphabet).
 *
 * The interop format for TOTP / HOTP secret sharing (Google
 * Authenticator, Authy) — MFA setup QR codes carry the shared secret
 * in this exact encoding. Decode is case-insensitive and tolerates
 * optional `=` padding; encode is uppercase and unpadded unless the
 * `padding` option is set.
 *
 * Throws plain `Error` / `TypeError` on malformed input. Callers that
 * need typed errors wrap the call at their surface boundary.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Reverse lookup: char → 5-bit value. Filled once at module load. */
const DECODE_TABLE = new Int8Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) {
  DECODE_TABLE[ALPHABET.charCodeAt(i)] = i;
  // Case-insensitive decode for letters only — digits (`2`-`7`) at code
  // points 50-55 would collide with letter aliases via `+32`.
  if (i < 26) {
    DECODE_TABLE[ALPHABET.charCodeAt(i) + 32] = i;
  }
}

/**
 * Encode bytes as an RFC 4648 §6 Base32 string (uppercase).
 *
 * @param {Buffer | Uint8Array} bytes
 * @param {{ padding?: boolean }} [options]  `padding: true` aligns the
 *   output to a multiple of 8 chars with `=` (RFC-strict form).
 * @returns {string}
 */
export function encode(bytes, options) {
  if (bytes == null || (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array))) {
    throw new TypeError('base32.encode: expected Buffer or Uint8Array');
  }
  const padding = options?.padding ?? false;

  // Keep `value` at ≤ 12 bits by masking after each emit — JS bitwise ops
  // are 32-bit signed, so accumulating 40+ bits into `value` would
  // silently drop the high bytes.
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

  if (padding) {
    while (out.length % 8 !== 0) {
      out += '=';
    }
  }
  return out;
}

/**
 * Decode a Base32 string into a Buffer. Accepts uppercase, lowercase
 * and mixed-case input; `=` padding is optional.
 *
 * @param {string} input
 * @returns {Buffer}
 */
export function decode(input) {
  if (typeof input !== 'string') {
    throw new TypeError('base32.decode: expected a string');
  }
  const clean = input.replace(/=+$/, '');
  const out = Buffer.alloc(Math.floor((clean.length * 5) / 8));

  // Same 32-bit masking rationale as encode.
  let bits = 0;
  let value = 0;
  let written = 0;
  for (let i = 0; i < clean.length; i++) {
    const c = clean.charCodeAt(i);
    const idx = c < 128 ? DECODE_TABLE[c] : -1;
    if (idx === -1) {
      throw new Error(`invalid base32 character '${clean[i]}' at index ${i}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[written++] = (value >>> bits) & 0xff;
      value &= (1 << bits) - 1;
    }
  }
  return out.subarray(0, written);
}
