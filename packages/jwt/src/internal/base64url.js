/**
 * `base64url` codec — RFC 4648 §5. Scaffold stub; the real codec lands
 * in the internal-utility-layer commit (copied verbatim from
 * `@exortek/jws` per the standalone-packages policy).
 */

import { JwtError, ErrorCode } from './errors.js';

/** @param {Buffer | Uint8Array} _bytes @returns {string} */
export function encode(_bytes) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'base64url.encode: not implemented');
}

/** @param {string} _text @returns {string} */
export function encodeString(_text) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'base64url.encodeString: not implemented');
}

/** @param {unknown} _value @returns {string} */
export function encodeJson(_value) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'base64url.encodeJson: not implemented');
}

/** @param {string} _text @returns {Buffer} */
export function decode(_text) {
  throw new JwtError(ErrorCode.INVALID_TOKEN, 'base64url.decode: not implemented');
}

/** @param {string} _text @returns {string} */
export function decodeString(_text) {
  throw new JwtError(ErrorCode.INVALID_TOKEN, 'base64url.decodeString: not implemented');
}

/** @param {string} _text @param {'header' | 'payload'} [_context] @returns {unknown} */
export function decodeJson(_text, _context) {
  throw new JwtError(ErrorCode.INVALID_HEADER, 'base64url.decodeJson: not implemented');
}
