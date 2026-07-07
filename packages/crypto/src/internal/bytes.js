import { CryptoError, ErrorCode } from '../errors.js';

/**
 * Coerce `value` (string / Buffer / Uint8Array) into a `Buffer`, throwing a
 * `CryptoError(INVALID_ARGUMENT)` for anything else.
 *
 * Strings are decoded as UTF-8; Buffers are passed through; Uint8Arrays are
 * wrapped without copying the underlying storage. Centralises the coercion
 * step used by every hash / hmac / encode / cipher input path.
 *
 * @param {unknown} value
 * @param {string}  name
 * @returns {Buffer}
 */
export function toBuffer(value, name) {
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

/**
 * Coerce `value` into a `Buffer`, decoding strings with the given output
 * encoding instead of UTF-8. Used on the receive side of a signature /
 * digest / token verify, where the caller passes an already-encoded blob
 * as a string and we need to reverse the encoding.
 *
 * @param {unknown} value
 * @param {string}  name
 * @param {'hex' | 'base64' | 'base64url'} encoding
 * @returns {Buffer}
 */
export function toBufferWithEncoding(value, name, encoding) {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  if (typeof value === 'string') {
    return Buffer.from(value, encoding);
  }
  throw new CryptoError(ErrorCode.INVALID_ARGUMENT, `${name} must be a string or Buffer`);
}
