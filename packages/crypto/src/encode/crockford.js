import * as sc from '@exortek/shared/crockford';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertString } from '@exortek/shared/asserts';
import { toBuffer } from '../internal/bytes.js';

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
 * encode(Buffer.from([0x00, 0xff]))   // '03ZG'
 * encode('Hello')                      // '91JPRV3F'
 */
export function encode(input) {
  return sc.encode(toBuffer(input, 'input'));
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
  try {
    return sc.decode(input);
  } catch (err) {
    throw new CryptoError(ErrorCode.INVALID_ENCODING, err.message, { cause: err });
  }
}
