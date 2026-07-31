/**
 * Unpadded `base64url` (RFC 4648 §5) — PASETO's payload/footer codec.
 * Wraps the shared implementation so decode failures surface as typed
 * `PasetoError(INVALID_TOKEN)`.
 */

import * as sb from '@exortek/shared/base64url';
import { PasetoError, ErrorCode } from './errors.js';

/** @param {Uint8Array | Buffer} bytes */
export function encode(bytes) {
  return sb.encode(bytes);
}

/**
 * @param {string} text
 * @returns {Buffer}
 */
export function decode(text) {
  try {
    return Buffer.from(sb.decode(text));
  } catch (err) {
    throw new PasetoError(ErrorCode.INVALID_TOKEN, `base64url: ${err.message}`, { cause: err });
  }
}
