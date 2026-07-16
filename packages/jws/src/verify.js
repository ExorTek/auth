/**
 * JWS Compact Serialization verification (RFC 7515 §7.1) plus detached
 * content (Appendix F) and unencoded payload (RFC 7797).
 *
 * The `alg` allowlist is **mandatory** on every call — omission raises
 * {@link ErrorCode.MISSING_ALG_ALLOWLIST}. `alg: 'none'` on the token
 * is refused up front with {@link ErrorCode.ALGORITHM_NONE_FORBIDDEN};
 * no flag can enable it.
 *
 * Scaffold stub; the real verifier lands in the compact-verify commit.
 */

import { JwsError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 * @typedef {import('./internal/resolver.js').KeyResolverFn} KeyResolverFn
 */

/**
 * @typedef {Object} VerifyOptions
 * @property {string[]} alg                                  REQUIRED. Accepted JOSE algorithm identifiers.
 * @property {Iterable<string>} [knownCriticalHeaders]       Extra `crit` names the verifier is prepared to process.
 * @property {number} [maxTokenSize]                         Default 8192 bytes. Larger tokens raise `TOKEN_TOO_LARGE`.
 */

/**
 * @typedef {Object} VerifyResult
 * @property {Record<string, unknown>} header    parsed protected header
 * @property {unknown} payload                    parsed payload (JSON when possible, Buffer otherwise)
 * @property {string | undefined} kid            resolved `kid` (from header or the matched key)
 */

/**
 * Verify a compact JWS.
 *
 * @param {string} _token
 * @param {KeyInput | KeyInput[] | KeyResolverFn} _keyish
 * @param {VerifyOptions} _options
 * @returns {Promise<VerifyResult>}
 */
export async function verify(_token, _keyish, _options) {
  throw new JwsError(ErrorCode.INVALID_ARGUMENT, 'verify: not implemented');
}

/**
 * Verify a detached-content JWS (RFC 7515 Appendix F). The caller
 * supplies the payload bytes separately from the token.
 *
 * @param {string} _token
 * @param {Buffer | Uint8Array} _detachedPayload
 * @param {KeyInput | KeyInput[] | KeyResolverFn} _keyish
 * @param {VerifyOptions} _options
 * @returns {Promise<VerifyResult>}
 */
export async function verifyDetached(_token, _detachedPayload, _keyish, _options) {
  throw new JwsError(ErrorCode.INVALID_ARGUMENT, 'verifyDetached: not implemented');
}
