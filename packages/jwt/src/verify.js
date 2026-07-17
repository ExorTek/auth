/**
 * JWT verification (RFC 7519 + RFC 8725). Signature check + full claims
 * validation (`exp`, `nbf`, `iat`, `iss`, `aud`, `sub`, `nonce`, `typ`,
 * `maxAge`, `requiredClaims`, `requiredScopes`).
 *
 * `alg` allowlist is **mandatory**. `alg: 'none'` is refused. `peek`
 * exposes a signature-verified payload without any claim checks — for
 * audit / logging where you need identity before token-lifecycle logic.
 *
 * Scaffold stub.
 */

import { JwtError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 * @typedef {import('./internal/resolver.js').KeyResolverFn} KeyResolverFn
 * @typedef {import('./claims.js').ClaimsOptions} ClaimsOptions
 *
 * @typedef {ClaimsOptions & {
 *   alg: string[],
 *   knownCriticalHeaders?: Iterable<string>,
 *   maxTokenSize?: number,
 * }} VerifyOptions
 *
 * @typedef {Object} VerifyResult
 * @property {Record<string, unknown>} header
 * @property {Record<string, unknown>} payload
 * @property {string | undefined} kid
 */

/**
 * @param {string} _token
 * @param {KeyInput | KeyInput[] | KeyResolverFn} _keyish
 * @param {VerifyOptions} _options
 * @returns {Promise<VerifyResult>}
 */
export async function verify(_token, _keyish, _options) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'verify: not implemented');
}

/**
 * Verify the signature but **skip claim validation** (no `exp`, `nbf`,
 * `iss`, `aud`, `maxAge`, `requiredClaims`, etc). Use for audit paths
 * where you need a trustworthy identity before deciding what to do
 * with an expired token. Never gate authorisation on this — use
 * `verify` for that.
 *
 * @param {string} _token
 * @param {KeyInput | KeyInput[] | KeyResolverFn} _keyish
 * @param {Pick<VerifyOptions, 'alg' | 'knownCriticalHeaders' | 'maxTokenSize'>} _options
 * @returns {Promise<VerifyResult>}
 */
export async function peek(_token, _keyish, _options) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'peek: not implemented');
}
