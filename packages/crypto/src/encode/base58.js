import { CryptoError, ErrorCode } from '../errors.js';
import { assertString } from '../internal/guards.js';
import { toBuffer } from '../internal/bytes.js';
import { BASE58 } from '../internal/alphabets.js';

/** Reverse lookup: char code → 6-bit value. Filled once at module load. */
const DECODE_TABLE = new Int8Array(128).fill(-1);
for (let i = 0; i < BASE58.length; i++) {
  DECODE_TABLE[BASE58.charCodeAt(i)] = i;
}

/**
 * Encode `input` as a Bitcoin-style Base58 string.
 *
 * Base58 (Satoshi's alphabet: `1-9A-HJ-NP-Za-km-z`) strips the four
 * look-alike glyphs `0`, `O`, `I`, `l` from Base64. Denser than hex,
 * safer to read out loud, safer to transcribe. Standard for Bitcoin /
 * Solana / Ripple addresses, Base58Check envelopes, and any short
 * human-visible ID (invite codes, invoice numbers, license keys).
 *
 * Leading zero bytes in `input` map to leading `'1'` characters in the
 * output, following the Base58Check convention — this preserves length
 * for fixed-width prefixes like an address version byte.
 *
 * @param {string | Buffer | Uint8Array} input
 * @returns {string}                     Base58-encoded string.
 * @throws {CryptoError}                 `INVALID_ARGUMENT` if `input` is
 *                                       neither a string nor a Buffer.
 *
 * @example
 * encode(Buffer.from([0x00, 0x00, 0xff]))   // '112C'
 * encode('hello')                            // 'Cn8eVZg'
 */
export function encode(input) {
  const buf = toBuffer(input, 'input');
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

  // Preserve leading zero bytes as leading '1' characters.
  for (let i = 0; i < buf.length && buf[i] === 0; i++) {
    out = '1' + out;
  }
  return out;
}

/**
 * Decode a Base58 string into a Buffer.
 *
 * The inverse of {@link encode}. Leading `'1'` characters map back to
 * leading zero bytes, matching the Base58Check convention.
 *
 * @param {string} input
 * @returns {Buffer}
 * @throws {CryptoError}   `INVALID_ARGUMENT` if `input` is not a string,
 *                          or `INVALID_ENCODING` if it contains characters
 *                          outside the Base58 alphabet (`0`, `O`, `I`, `l`
 *                          are all invalid on purpose).
 *
 * @example
 * decode('Cn8eVZg')   // Buffer('hello')
 * decode('112C')      // Buffer([0x00, 0x00, 0xff])
 */
export function decode(input) {
  assertString(input, 'input');
  if (input.length === 0) {
    return Buffer.alloc(0);
  }

  let n = 0n;
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    const v = code < 128 ? DECODE_TABLE[code] : -1;
    if (v === -1) {
      throw new CryptoError(
        ErrorCode.INVALID_ENCODING,
        `input contains a non-Base58 character '${input[i]}' at index ${i}. Base58 alphabet is 1-9 A-H J-N P-Z a-k m-z (skips 0, O, I, l).`,
      );
    }
    n = n * 58n + BigInt(v);
  }

  const bytes = [];
  while (n > 0n) {
    bytes.push(Number(n & 0xffn));
    n >>= 8n;
  }
  bytes.reverse();

  // Preserve leading '1' characters as leading zero bytes.
  let zeros = 0;
  while (zeros < input.length && input.charCodeAt(zeros) === 49 /* '1' */) {
    zeros++;
  }
  return Buffer.concat([Buffer.alloc(zeros), Buffer.from(bytes)]);
}
