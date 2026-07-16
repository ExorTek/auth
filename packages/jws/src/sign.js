/**
 * JWS Compact Serialization signing (RFC 7515 §7.1) plus detached
 * content (Appendix F) and unencoded payload (RFC 7797).
 *
 * `alg` is **mandatory** on every call — there is no default. `none`
 * is refused up front with a dedicated error code so the diagnostic is
 * actionable rather than "unsupported algorithm".
 *
 * Scaffold stub; the real signer lands in the compact-sign commit.
 */

import { JwsError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 */

/**
 * @typedef {Object} SignOptions
 * @property {string} alg                                 REQUIRED. JOSE algorithm identifier.
 * @property {string} [kid]                               `kid` header shortcut.
 * @property {Record<string, unknown>} [header]           Extra protected header parameters.
 * @property {Record<string, unknown>} [unprotected]      JSON-serialisation only.
 * @property {boolean} [b64]                              RFC 7797. Default true.
 * @property {string[]} [crit]                            Marks header names as critical (RFC 7515 §4.1.11).
 */

/**
 * Sign a payload and return a compact JWS.
 *
 * @param {unknown} _payload   JSON-serialisable value or a `Buffer` for raw bytes.
 * @param {KeyInput} _key
 * @param {SignOptions} _options
 * @returns {Promise<string>}
 */
export async function sign(_payload, _key, _options) {
  throw new JwsError(ErrorCode.INVALID_ARGUMENT, 'sign: not implemented');
}

/**
 * Sign a payload with the RFC 7515 Appendix F detached-content variant.
 * Returns `{ token, detached }` — `token` has the payload segment
 * blanked out; `detached` is the raw payload bytes the verifier needs
 * to supply back on `verifyDetached`.
 *
 * @param {Buffer | Uint8Array} _payload
 * @param {KeyInput} _key
 * @param {SignOptions} _options
 * @returns {Promise<{ token: string, detached: Buffer }>}
 */
export async function signDetached(_payload, _key, _options) {
  throw new JwsError(ErrorCode.INVALID_ARGUMENT, 'signDetached: not implemented');
}
