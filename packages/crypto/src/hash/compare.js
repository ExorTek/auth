import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';

/**
 * Timing-safe equality check for hash digests, tokens, MACs and any other
 * secret-comparable strings.
 *
 * Wraps `crypto.timingSafeEqual` so that comparison runtime is independent
 * of matching-prefix length — closes the classic side-channel where a
 * naive `===` reveals character positions to an attacker measuring
 * response time.
 *
 * Accepts strings or Buffers/Uint8Arrays; strings are compared byte-by-byte
 * in UTF-8. When lengths differ, returns `false` immediately (the length
 * of a hash is not itself a secret — different algorithms produce
 * well-known digest sizes).
 *
 * @param {string | Buffer | Uint8Array} a
 * @param {string | Buffer | Uint8Array} b
 * @returns {boolean}
 * @throws {CryptoError} With code `INVALID_ARGUMENT` if either input is neither
 *                       a string nor a Buffer/Uint8Array.
 *
 * @example
 * const stored = hash(providedPassword)
 * if (!compare(stored, dbRecord.hash)) throw new Error('bad credentials')
 *
 * @example
 * // Also safe for HMAC verification:
 * if (!compare(receivedSig, hmac(payload, key))) throw new Error('bad signature')
 */
export function compare(a, b) {
  const bufA = _toBuffer(a, 'a');
  const bufB = _toBuffer(b, 'b');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * @private
 * @param {unknown} value
 * @param {string}  name
 * @returns {Buffer}
 */
function _toBuffer(value, name) {
  if (typeof value === 'string') {
    return Buffer.from(value, 'utf8');
  }
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new CryptoError(ErrorCode.INVALID_ARGUMENT, `${name} must be a string or Buffer`);
}
