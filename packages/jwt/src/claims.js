/**
 * Claims validation — RFC 7519 §4 + RFC 8725 (best practice).
 *
 * Validates the standard registered claims (`exp`, `nbf`, `iat`, `iss`,
 * `aud`, `sub`, `jti`) plus the OIDC `nonce`, `typ` header enforcement,
 * `maxAge` (iat freshness), `requiredClaims`, and OAuth2 `scope` /
 * `scp`.
 *
 * Scaffold stub. Implementation lands in the claims-layer commit.
 */

import { JwtError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {Object} ClaimsOptions
 * @property {string | string[] | RegExp | Array<string | RegExp> | ((claimed: string) => boolean | Promise<boolean>)} [issuer]
 * @property {string | string[] | RegExp | Array<string | RegExp> | ((claimed: string) => boolean | Promise<boolean>)} [audience]
 * @property {string} [subject]
 * @property {string} [nonce]
 * @property {string | string[]} [typ]
 * @property {string[]} [requiredClaims]
 * @property {string[]} [requiredScopes]
 * @property {number | string} [clockTolerance]  seconds or duration string
 * @property {number | string} [maxAge]           duration for iat freshness
 * @property {Date} [currentDate]                 override "now" for testing
 */

/**
 * @param {Record<string, unknown>} _payload
 * @param {Record<string, unknown>} _header
 * @param {ClaimsOptions} [_options]
 * @returns {Promise<void>}
 */
export async function validateClaims(_payload, _header, _options) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'claims.validateClaims: not implemented');
}

/**
 * Build the payload the signer will encode — injects `exp`, `nbf`,
 * `iat`, `jti`, `iss`, `aud`, `sub`, `nonce` per options.
 *
 * @param {Record<string, unknown>} _payload
 * @param {Object} [_options]
 * @returns {Promise<Record<string, unknown>>}
 */
export async function injectClaims(_payload, _options) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'claims.injectClaims: not implemented');
}
