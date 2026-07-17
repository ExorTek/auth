/**
 * **UNSAFE** JWT inspection — parses header + payload + signature
 * without verifying anything. Use for `kid` extraction before picking
 * a key resolver, or debugging a token from a log. Never gate
 * authorisation on this.
 */

import { JwtError, ErrorCode } from './internal/errors.js';
import { decode as b64uDecode, decodeJson as b64uDecodeJson } from './internal/base64url.js';

/**
 * @typedef {Object} DecodedJwt
 * @property {Record<string, unknown>} header
 * @property {Record<string, unknown>} payload
 * @property {Buffer} signature
 */

/**
 * @param {string} token
 * @returns {DecodedJwt}
 */
export function decode(token) {
  const { encHeader, encPayload, encSig } = _splitCompact(token);
  const header = /** @type {Record<string, unknown>} */ (b64uDecodeJson(encHeader, 'header'));
  const payload = /** @type {Record<string, unknown>} */ (b64uDecodeJson(encPayload, 'payload'));
  const signature = b64uDecode(encSig);
  return { header, payload, signature };
}

/**
 * @param {string} token
 * @returns {Record<string, unknown>}
 */
export function decodeProtectedHeader(token) {
  if (typeof token !== 'string') {
    throw new JwtError(ErrorCode.INVALID_TOKEN, 'decodeProtectedHeader: expected a string token');
  }
  const dot = token.indexOf('.');
  if (dot === -1) {
    throw new JwtError(ErrorCode.INVALID_TOKEN, 'decodeProtectedHeader: token is not a compact JWS (no "." separator)');
  }
  return /** @type {Record<string, unknown>} */ (b64uDecodeJson(token.slice(0, dot), 'header'));
}

/**
 * Split a compact JWT into its three base64url segments. Exported for
 * internal reuse by `verify` and `peek`.
 *
 * @param {string} token
 * @returns {{ encHeader: string, encPayload: string, encSig: string }}
 */
export function _splitCompact(token) {
  if (typeof token !== 'string') {
    throw new JwtError(ErrorCode.INVALID_TOKEN, 'JWT: expected a string token');
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new JwtError(ErrorCode.INVALID_TOKEN, `JWT: expected 3 "."-separated segments, got ${parts.length}`);
  }
  const [encHeader, encPayload, encSig] = parts;
  return { encHeader, encPayload, encSig };
}
