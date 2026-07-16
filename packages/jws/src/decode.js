/**
 * UNSAFE compact-JWS inspection — parses the header and payload without
 * verifying the signature. **Never gate authorisation on this.**
 *
 * Use case: extracting `kid` before choosing a key resolver; debugging
 * a token from a log. Anything real must go through `verify`.
 *
 * Scaffold stub; the real decoder lands in the compact-verify commit
 * (it is a strict subset of what `verify` needs to do to reach the
 * signature check).
 */

import { JwsError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {Object} DecodedJws
 * @property {Record<string, unknown>} header
 * @property {unknown} payload
 * @property {Buffer} signature
 */

/**
 * @param {string} _token
 * @returns {DecodedJws}
 */
export function decode(_token) {
  throw new JwsError(ErrorCode.INVALID_ARGUMENT, 'decode: not implemented');
}

/**
 * Return just the protected header. Handy for `kid` extraction.
 *
 * @param {string} _token
 * @returns {Record<string, unknown>}
 */
export function decodeProtectedHeader(_token) {
  throw new JwsError(ErrorCode.INVALID_ARGUMENT, 'decodeProtectedHeader: not implemented');
}
