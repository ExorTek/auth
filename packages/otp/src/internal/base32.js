// RFC 4648 Base32 codec (upper-case A-Z 2-7 alphabet). Small, stable,
// hot-path only during enrollment / paste — we don't optimize past
// clarity. Case-insensitive on decode, no padding on encode (matches
// the Google Authenticator display convention).

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const CHARSET = new Uint8Array(128);

// Reverse lookup table (uppercase). Fill with 0xff = "not a base32 char".
CHARSET.fill(0xff);
for (let i = 0; i < ALPHABET.length; i++) {
  CHARSET[ALPHABET.charCodeAt(i)] = i;
  // Accept lowercase too — users paste in whatever case.
  CHARSET[ALPHABET.toLowerCase().charCodeAt(i)] = i;
}

/**
 * Encode bytes to unpadded base32.
 * @param {Buffer | Uint8Array} bytes
 * @returns {string}
 */
export function encode(bytes) {
  let out = '';
  let bits = 0;
  let value = 0;

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(value >>> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    out += ALPHABET[(value << (5 - bits)) & 0x1f];
  }
  return out;
}

/**
 * Decode a base32 string to a Buffer. Accepts padded / unpadded,
 * upper / lower / mixed case. Throws on any character outside the
 * alphabet.
 * @param {string} input
 * @returns {Buffer}
 */
export function decode(input) {
  // Strip padding — spec allows both.
  const clean = input.replace(/=+$/, '');
  const out = Buffer.alloc(Math.floor((clean.length * 5) / 8));

  let bits = 0;
  let value = 0;
  let written = 0;
  for (let i = 0; i < clean.length; i++) {
    const c = clean.charCodeAt(i);
    const idx = c < 128 ? CHARSET[c] : 0xff;
    if (idx === 0xff) {
      throw new Error(`invalid base32 character '${clean[i]}' at index ${i}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[written++] = (value >>> bits) & 0xff;
    }
  }
  return out.slice(0, written);
}
