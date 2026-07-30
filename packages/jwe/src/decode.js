/**
 * UNSAFE compact-JWE inspection — parses the protected header and splits
 * the five segments **without** decrypting. **Never gate authorisation on
 * this.**
 *
 * Use case: extracting `alg` / `enc` / `kid` before choosing a key
 * resolver; debugging a token from a log. Anything real must go through
 * `decrypt`.
 */

import { JweError, ErrorCode } from './internal/errors.js';
import { decode as b64uDecode, decodeJson as b64uDecodeJson } from './internal/base64url.js';

/**
 * @typedef {Object} DecodedJwe
 * @property {Record<string, unknown>} header  Protected (JOSE) header.
 * @property {Buffer} encryptedKey  Wrapped CEK (empty for `dir` / `ECDH-ES`).
 * @property {Buffer} iv  Content-encryption Initialization Vector.
 * @property {Buffer} ciphertext  The AEAD ciphertext.
 * @property {Buffer} tag  The AEAD authentication tag.
 */

/**
 * Split and decode a compact JWE without decrypting it.
 *
 * @param {string} token
 * @returns {DecodedJwe}
 */
export function decode(token) {
  const { encHeader, encKey, encIv, encCiphertext, encTag } = _splitCompact(token);
  const header = /** @type {Record<string, unknown>} */ (b64uDecodeJson(encHeader));
  // The encrypted-key segment is empty for `dir` and bare `ECDH-ES`.
  const encryptedKey = encKey === '' ? Buffer.alloc(0) : b64uDecode(encKey);
  return {
    header,
    encryptedKey,
    iv: b64uDecode(encIv),
    ciphertext: b64uDecode(encCiphertext),
    tag: b64uDecode(encTag),
  };
}

/**
 * Return only the protected header. Handy for `alg` / `enc` / `kid`
 * extraction before calling `decrypt` with a resolver.
 *
 * @param {string} token
 * @returns {Record<string, unknown>}
 */
export function decodeProtectedHeader(token) {
  if (typeof token !== 'string') {
    throw new JweError(ErrorCode.INVALID_TOKEN, 'decodeProtectedHeader: expected a string token');
  }
  const dot = token.indexOf('.');
  if (dot === -1) {
    throw new JweError(ErrorCode.INVALID_TOKEN, 'decodeProtectedHeader: token is not a compact JWE (no "." separator)');
  }
  return /** @type {Record<string, unknown>} */ (b64uDecodeJson(token.slice(0, dot)));
}

/**
 * Split a compact JWE into its five base64url segments — protected
 * header, encrypted key, IV, ciphertext, authentication tag (RFC 7516
 * §3.1 / §7.1). Exported for internal reuse by `decrypt`.
 *
 * @param {string} token
 * @returns {{ encHeader: string, encKey: string, encIv: string, encCiphertext: string, encTag: string }}
 */
export function _splitCompact(token) {
  if (typeof token !== 'string') {
    throw new JweError(ErrorCode.INVALID_TOKEN, 'compact JWE: expected a string token');
  }
  const parts = token.split('.');
  if (parts.length !== 5) {
    throw new JweError(ErrorCode.INVALID_TOKEN, `compact JWE: expected 5 "."-separated segments, got ${parts.length}`);
  }
  const [encHeader, encKey, encIv, encCiphertext, encTag] = parts;
  return { encHeader, encKey, encIv, encCiphertext, encTag };
}
