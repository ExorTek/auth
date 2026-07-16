/**
 * UNSAFE compact-JWS inspection — parses the header and payload without
 * verifying the signature. **Never gate authorisation on this.**
 *
 * Use case: extracting `kid` before choosing a key resolver; debugging
 * a token from a log. Anything real must go through `verify`.
 */

import { JwsError, ErrorCode } from './internal/errors.js';
import { decode as b64uDecode, decodeJson as b64uDecodeJson } from './internal/base64url.js';

/**
 * @typedef {Object} DecodedJws
 * @property {Record<string, unknown>} header
 * @property {unknown} payload
 * @property {Buffer} signature
 */

/**
 * @param {string} token
 * @returns {DecodedJws}
 */
export function decode(token) {
  const { encHeader, encPayload, encSig } = _splitCompact(token);
  const header = /** @type {Record<string, unknown>} */ (b64uDecodeJson(encHeader, 'header'));
  const payload = _decodePayload(header, encPayload);
  const signature = b64uDecode(encSig);
  return { header, payload, signature };
}

/**
 * Return only the protected header. Handy for `kid` / `alg` extraction
 * before calling `verify` with a resolver.
 *
 * @param {string} token
 * @returns {Record<string, unknown>}
 */
export function decodeProtectedHeader(token) {
  if (typeof token !== 'string') {
    throw new JwsError(ErrorCode.INVALID_TOKEN, 'decodeProtectedHeader: expected a string token');
  }
  const dot = token.indexOf('.');
  if (dot === -1) {
    throw new JwsError(ErrorCode.INVALID_TOKEN, 'decodeProtectedHeader: token is not a compact JWS (no "." separator)');
  }
  return /** @type {Record<string, unknown>} */ (b64uDecodeJson(token.slice(0, dot), 'header'));
}

/**
 * Split a compact JWS into its three base64url segments. Exported for
 * internal reuse by `verify`.
 *
 * @param {string} token
 * @returns {{ encHeader: string, encPayload: string, encSig: string }}
 */
export function _splitCompact(token) {
  if (typeof token !== 'string') {
    throw new JwsError(ErrorCode.INVALID_TOKEN, 'compact JWS: expected a string token');
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new JwsError(ErrorCode.INVALID_TOKEN, `compact JWS: expected 3 "."-separated segments, got ${parts.length}`);
  }
  const [encHeader, encPayload, encSig] = parts;
  return { encHeader, encPayload, encSig };
}

/**
 * Payload decoding shared by `decode` and `verify`. Honours RFC 7797
 * (`b64: false` unencoded payload) and falls back to raw bytes if the
 * value isn't JSON.
 *
 * @param {Record<string, unknown>} header
 * @param {string} encPayload
 */
export function _decodePayload(header, encPayload) {
  if (header.b64 === false) {
    // RFC 7797: the compact segment is the payload as-is, no base64url step.
    return encPayload;
  }
  try {
    return b64uDecodeJson(encPayload, 'payload');
  } catch {
    // Non-JSON payload — hand back the raw bytes.
    return b64uDecode(encPayload);
  }
}
