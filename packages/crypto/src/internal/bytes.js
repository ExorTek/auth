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
