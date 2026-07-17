/**
 * **UNSAFE** JWT inspection — parses header + payload + signature
 * without verifying anything. Use for `kid` extraction before picking
 * a key resolver, or debugging a token from a log. Never gate
 * authorisation on this.
 *
 * Scaffold stub.
 */

import { JwtError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {Object} DecodedJwt
 * @property {Record<string, unknown>} header
 * @property {Record<string, unknown>} payload
 * @property {Buffer} signature
 */

/**
 * @param {string} _token
 * @returns {DecodedJwt}
 */
export function decode(_token) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'decode: not implemented');
}

/**
 * @param {string} _token
 * @returns {Record<string, unknown>}
 */
export function decodeProtectedHeader(_token) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'decodeProtectedHeader: not implemented');
}
