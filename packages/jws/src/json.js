/**
 * JWS JSON Serialization — general (multi-signature) and flattened
 * (single) forms per RFC 7515 §7.2.
 *
 * Scaffold stub; the real serialiser + verifier land in the JSON-
 * serialization commit.
 */

import { JwsError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 * @typedef {import('./sign.js').SignOptions} SignOptions
 * @typedef {import('./verify.js').VerifyOptions} VerifyOptions
 */

/**
 * @typedef {Object} SignSpec
 * @property {KeyInput} key
 * @property {SignOptions} options
 */

/**
 * @typedef {Object} GeneralJws
 * @property {string} payload
 * @property {Array<{ protected: string, header?: object, signature: string }>} signatures
 */

/**
 * @typedef {Object} FlattenedJws
 * @property {string} payload
 * @property {string} protected
 * @property {object} [header]
 * @property {string} signature
 */

/**
 * Sign a payload with one or more keys producing a JWS JSON serialisation.
 * A single-entry array becomes the flattened form; multiple entries
 * become the general form.
 *
 * @param {unknown} _payload
 * @param {SignSpec[]} _signers
 * @returns {Promise<GeneralJws | FlattenedJws>}
 */
export async function signJson(_payload, _signers) {
  throw new JwsError(ErrorCode.INVALID_ARGUMENT, 'signJson: not implemented');
}

/**
 * Verify a JWS JSON serialisation. Accepts either the general or
 * flattened shape. When multiple signatures are present the first one
 * whose key resolves + signature checks out wins; the rest are
 * inspected only to surface tamper markers.
 *
 * @param {GeneralJws | FlattenedJws} _jws
 * @param {import('./internal/keys.js').KeyInput | import('./internal/keys.js').KeyInput[] | import('./internal/resolver.js').KeyResolverFn} _keyish
 * @param {VerifyOptions} _options
 * @returns {Promise<{ header: object, payload: unknown, kid?: string, matchedSignatureIndex: number }>}
 */
export async function verifyJson(_jws, _keyish, _options) {
  throw new JwsError(ErrorCode.INVALID_ARGUMENT, 'verifyJson: not implemented');
}
