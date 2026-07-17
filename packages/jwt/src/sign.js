/**
 * JWT signing (RFC 7519). Emits a compact JWS carrying the claims set.
 *
 * `alg` is **mandatory** on every call. `alg: 'none'` is refused up
 * front. `expiresIn` accepts either a NumericDate seconds integer or a
 * human duration (`'15m'`, `'7d'`, `'2h'`). `noTimestamp: true` skips
 * the auto `iat` inject. `returnMetadata: true` returns
 * `{ token, jti, expiresAt, issuedAt, alg, kid }` instead of just the
 * token string.
 *
 * Scaffold stub.
 */

import { JwtError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 *
 * @typedef {Object} SignOptions
 * @property {string} alg                                   REQUIRED. JOSE algorithm.
 * @property {string | number} [expiresIn]                  Duration string or NumericDate seconds — sets `exp`.
 * @property {string | number} [notBefore]                  Sets `nbf`.
 * @property {string} [issuer]                              Sets `iss`.
 * @property {string | string[]} [audience]                 Sets `aud` (string or array).
 * @property {string} [subject]                             Sets `sub`.
 * @property {boolean | { size?: number, encoding?: string } | (() => string | Promise<string>)} [jwtId]
 * @property {string} [nonce]                               Sets `nonce` (OIDC).
 * @property {string} [typ]                                 Header `typ`. Default `'JWT'`. `'at+jwt'` for RFC 9068.
 * @property {string} [kid]                                 Header `kid` shortcut.
 * @property {Record<string, unknown>} [header]             Extra header parameters.
 * @property {boolean} [noTimestamp]                        Skip auto `iat`.
 * @property {boolean} [returnMetadata]                     Return `{ token, jti, expiresAt, ... }` instead of string.
 */

/**
 * @param {Record<string, unknown>} _payload
 * @param {KeyInput} _key
 * @param {SignOptions} _options
 * @returns {Promise<string | { token: string, jti?: string, expiresAt?: Date, issuedAt?: Date, alg: string, kid?: string }>}
 */
export async function sign(_payload, _key, _options) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'sign: not implemented');
}
