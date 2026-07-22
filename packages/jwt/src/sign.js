/**
 * JWT signing (RFC 7519). Emits a compact JWS carrying the claims set.
 *
 * `alg` is **mandatory** on every call. `alg: 'none'` is refused up
 * front. Full claims injection (`exp` / `nbf` / `iat` / `iss` / `aud` /
 * `sub` / `jti` / `nonce`) + duration parsing and the metadata-return
 * shape land in the claims-layer / DX commits; this file already
 * accepts those options so their integration is additive.
 */

import { isNumber, isObject, isString } from '@exortek/shared/predicates';

import { JwtError, ErrorCode } from './internal/errors.js';
import { assertNonEmptyString, assertObject } from './internal/guards.js';
import { lookup as lookupAlg } from './internal/algorithms.js';
import { normalizeKey } from './internal/keys.js';
import { encode as b64uEncode, encodeJson as b64uEncodeJson } from './internal/base64url.js';
import { injectClaims } from './claims.js';

/**
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 *
 * @typedef {Object} SignOptions
 * @property {string} alg
 * @property {string | number} [expiresIn]
 * @property {string | number} [notBefore]
 * @property {string} [issuer]
 * @property {string | string[]} [audience]
 * @property {string} [subject]
 * @property {boolean | { size?: number, encoding?: string } | (() => string | Promise<string>)} [jwtId]
 * @property {string} [nonce]
 * @property {string} [typ]                                  Header `typ`. Default `'JWT'`. `'at+jwt'` for RFC 9068.
 * @property {string} [kid]
 * @property {Record<string, unknown>} [header]
 * @property {boolean} [noTimestamp]
 * @property {boolean} [returnMetadata]
 *
 * @typedef {Object} SignResultMeta
 * @property {string} token
 * @property {string} [jti]
 * @property {Date} [expiresAt]
 * @property {Date} [issuedAt]
 * @property {string} alg
 * @property {string} [kid]
 */

/**
 * @param {Record<string, unknown>} payload
 * @param {KeyInput} key
 * @param {SignOptions} options
 * @returns {Promise<string | SignResultMeta>}
 */
export async function sign(payload, key, options) {
  assertObject(options, 'sign.options');
  if (!isObject(payload)) {
    throw new JwtError(ErrorCode.INVALID_PAYLOAD, 'sign: payload must be a JSON object');
  }
  assertNonEmptyString(options.alg, 'sign.options.alg');
  const alg = options.alg;
  if (alg === 'none') {
    throw new JwtError(
      ErrorCode.ALGORITHM_NONE_FORBIDDEN,
      'sign: alg "none" is refused unconditionally (RFC 8725 §3.1)',
    );
  }

  const meta = lookupAlg(alg);
  const keyObj = await normalizeKey(key, alg, 'sign');

  const claimSet = await injectClaims(payload, options);
  const header = _buildHeader(alg, options);

  const encHeader = b64uEncodeJson(header);
  const encPayload = b64uEncodeJson(claimSet);
  const signingInput = Buffer.from(`${encHeader}.${encPayload}`, 'utf8');
  const signature = await meta.sign(keyObj, signingInput);
  const encSig = b64uEncode(signature);

  const token = `${encHeader}.${encPayload}.${encSig}`;

  if (!options.returnMetadata) {
    return token;
  }

  /** @type {SignResultMeta} */
  const result = { token, alg };
  if (isString(header.kid)) {
    result.kid = header.kid;
  }
  if (isString(claimSet.jti)) {
    result.jti = claimSet.jti;
  }
  if (isNumber(claimSet.exp)) {
    result.expiresAt = new Date(claimSet.exp * 1000);
  }
  if (isNumber(claimSet.iat)) {
    result.issuedAt = new Date(claimSet.iat * 1000);
  }
  return result;
}

/**
 * @param {string} alg
 * @param {SignOptions} options
 * @returns {Record<string, unknown>}
 */
function _buildHeader(alg, options) {
  /** @type {Record<string, unknown>} */
  const header = { alg };
  if (options.typ !== undefined) {
    if (typeof options.typ !== 'string') {
      throw new JwtError(ErrorCode.INVALID_HEADER, 'sign: `typ` must be a string when set');
    }
    header.typ = options.typ;
  } else {
    header.typ = 'JWT';
  }
  if (options.kid !== undefined) {
    header.kid = options.kid;
  }
  if (isObject(options.header)) {
    for (const [k, v] of Object.entries(options.header)) {
      if (k === 'alg') {
        continue;
      }
      header[k] = v;
    }
  }
  return header;
}
