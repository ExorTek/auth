/**
 * JWK shape validation — RFC 7517 §4 (common) + RFC 7518 §6 (per-kty) +
 * RFC 8037 §2 (OKP).
 *
 * `validate()` is strict by default: unknown members are preserved but
 * required members must be present, base64url payloads must decode to
 * the correct byte length, and (optionally) `use` / `key_ops` are checked
 * for the consistency rule from RFC 7517 §4.3.
 */

import { isArray, isObject } from '@exortek/shared/predicates';

import { JwkError, ErrorCode } from './internal/errors.js';
import { decodeMember } from './internal/base64url.js';
import { EC_COORD_BYTES, EC_CURVES, OKP_CURVES, OKP_KEY_BYTES } from './internal/curves.js';

const VALID_USE = new Set(['sig', 'enc']);
const VALID_KEY_OPS = new Set([
  'sign',
  'verify',
  'encrypt',
  'decrypt',
  'wrapKey',
  'unwrapKey',
  'deriveKey',
  'deriveBits',
]);

/**
 * Operations compatible with each `use` value per RFC 7517 §4.3. When
 * both `use` and `key_ops` are present the JWK MUST be consistent — every
 * op the JWK claims has to fall into the allowlist that matches its `use`.
 */
const KEY_OPS_FOR_USE = Object.freeze({
  sig: new Set(['sign', 'verify']),
  enc: new Set(['encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'deriveKey', 'deriveBits']),
});

/**
 * @typedef {Object} ValidateOptions
 * @property {boolean} [requirePrivate=false] reject public-only JWKs
 * @property {boolean} [requirePublic=false]  reject secret-carrying JWKs
 */

/**
 * Assert that `jwk` conforms to the RFC 7517 shape and its per-kty
 * requirements. Returns the JWK unchanged when valid; throws
 * {@link JwkError} otherwise.
 *
 * @param {unknown} jwk
 * @param {ValidateOptions} [options]
 * @returns {object} the same JWK, narrowed to a validated shape
 */
export function validate(jwk, options) {
  if (!isObject(jwk)) {
    throw new JwkError(ErrorCode.INVALID_JWK, 'validate: expected a JWK object');
  }
  const j = /** @type {Record<string, unknown>} */ (jwk);
  const kty = j.kty;
  if (typeof kty !== 'string') {
    throw new JwkError(ErrorCode.MISSING_REQUIRED_MEMBER, 'validate: `kty` is required (RFC 7517 §4.1)');
  }
  _validateCommon(j);
  const isPrivate = _validateByKty(j, kty);

  const opts = options || {};
  if (opts.requirePrivate && !isPrivate) {
    throw new JwkError(
      ErrorCode.INVALID_JWK,
      `validate: requirePrivate=true but the JWK carries no secret material (${kty})`,
    );
  }
  if (opts.requirePublic && isPrivate) {
    throw new JwkError(
      ErrorCode.INVALID_JWK,
      `validate: requirePublic=true but the JWK carries secret material (${kty})`,
    );
  }
  return jwk;
}

/**
 * Non-throwing variant. Returns `true` when the JWK passes
 * {@link validate}, `false` otherwise. Handy for JWKS filtering.
 *
 * @param {unknown} jwk
 * @param {ValidateOptions} [options]
 * @returns {boolean}
 */
export function isValid(jwk, options) {
  try {
    validate(jwk, options);
    return true;
  } catch (err) {
    if (err instanceof JwkError) {
      return false;
    }
    throw err;
  }
}

/**
 * @param {Record<string, unknown>} j
 */
function _validateCommon(j) {
  if (j.kid !== undefined && typeof j.kid !== 'string') {
    throw new JwkError(ErrorCode.INVALID_JWK, 'validate: `kid` must be a string when present');
  }
  if (j.use !== undefined) {
    if (typeof j.use !== 'string' || !VALID_USE.has(j.use)) {
      throw new JwkError(
        ErrorCode.INVALID_JWK,
        `validate: \`use\` must be one of "sig" | "enc", got ${JSON.stringify(j.use)}`,
      );
    }
  }
  if (j.alg !== undefined && typeof j.alg !== 'string') {
    throw new JwkError(ErrorCode.INVALID_JWK, 'validate: `alg` must be a string when present');
  }
  if (j.key_ops !== undefined) {
    if (!isArray(j.key_ops)) {
      throw new JwkError(ErrorCode.INVALID_JWK, 'validate: `key_ops` must be an array of strings');
    }
    /** @type {Set<string>} */
    const seen = new Set();
    for (const op of j.key_ops) {
      if (typeof op !== 'string' || !VALID_KEY_OPS.has(op)) {
        throw new JwkError(
          ErrorCode.INVALID_JWK,
          `validate: \`key_ops\` contains invalid entry ${JSON.stringify(op)} (RFC 7517 §4.3)`,
        );
      }
      if (seen.has(op)) {
        throw new JwkError(
          ErrorCode.INVALID_JWK,
          `validate: \`key_ops\` contains duplicate ${JSON.stringify(op)} — RFC 7517 §4.3 forbids duplicates`,
        );
      }
      seen.add(op);
    }
    if (j.use !== undefined) {
      const allowed = KEY_OPS_FOR_USE[/** @type {'sig' | 'enc'} */ (j.use)];
      for (const op of /** @type {string[]} */ (j.key_ops)) {
        if (!allowed.has(op)) {
          throw new JwkError(
            ErrorCode.KEY_OPS_CONFLICT,
            `validate: \`use\` = ${JSON.stringify(j.use)} conflicts with \`key_ops\` entry ${JSON.stringify(op)} — RFC 7517 §4.3 requires consistency (allowed for "${j.use}": ${[...allowed].join(', ')})`,
          );
        }
      }
    }
  }
}

/**
 * @param {Record<string, unknown>} j
 * @param {string} kty
 * @returns {boolean} true when the JWK carries private / secret material
 */
function _validateByKty(j, kty) {
  switch (kty) {
    case 'EC':
      return _validateEC(j);
    case 'RSA':
      return _validateRSA(j);
    case 'oct':
      return _validateOct(j);
    case 'OKP':
      return _validateOKP(j);
    default:
      throw new JwkError(
        ErrorCode.UNSUPPORTED_KTY,
        `validate: unsupported kty ${JSON.stringify(kty)} — expected "EC" | "RSA" | "oct" | "OKP"`,
      );
  }
}

/** @param {Record<string, unknown>} j */
function _validateEC(j) {
  const crv = j.crv;
  if (typeof crv !== 'string' || !(crv in EC_CURVES)) {
    throw new JwkError(
      ErrorCode.UNSUPPORTED_CURVE,
      `validate: EC \`crv\` must be one of ${Object.keys(EC_CURVES).join(' | ')}, got ${JSON.stringify(crv)}`,
    );
  }
  const size = EC_COORD_BYTES[/** @type {keyof typeof EC_COORD_BYTES} */ (crv)];
  _requireString(j, 'x');
  _requireString(j, 'y');
  decodeMember(/** @type {string} */ (j.x), 'EC.x', size);
  decodeMember(/** @type {string} */ (j.y), 'EC.y', size);
  if (j.d !== undefined) {
    _requireString(j, 'd');
    decodeMember(/** @type {string} */ (j.d), 'EC.d', size);
    return true;
  }
  return false;
}

/** @param {Record<string, unknown>} j */
function _validateRSA(j) {
  _requireString(j, 'n');
  _requireString(j, 'e');
  decodeMember(/** @type {string} */ (j.n), 'RSA.n');
  decodeMember(/** @type {string} */ (j.e), 'RSA.e');
  if (j.d !== undefined) {
    _requireString(j, 'd');
    decodeMember(/** @type {string} */ (j.d), 'RSA.d');
    // CRT parameters are optional per RFC 7518 §6.3.2; if any is present
    // Node's key import path expects the full set. We warn via error only
    // if the set is partially populated.
    const crt = ['p', 'q', 'dp', 'dq', 'qi'];
    const present = crt.filter(name => j[name] !== undefined);
    if (present.length > 0 && present.length < crt.length) {
      throw new JwkError(
        ErrorCode.INVALID_JWK,
        `validate: RSA private JWK has partial CRT parameters (${present.join(', ')}) — provide all of ${crt.join(', ')} or none (RFC 7518 §6.3.2)`,
      );
    }
    for (const name of present) {
      _requireString(j, name);
      decodeMember(/** @type {string} */ (j[name]), `RSA.${name}`);
    }
    return true;
  }
  return false;
}

/** @param {Record<string, unknown>} j */
function _validateOct(j) {
  _requireString(j, 'k');
  const bytes = decodeMember(/** @type {string} */ (j.k), 'oct.k');
  if (bytes.length === 0) {
    throw new JwkError(ErrorCode.INVALID_JWK, 'validate: oct `k` decodes to zero bytes');
  }
  return true;
}

/** @param {Record<string, unknown>} j */
function _validateOKP(j) {
  const crv = j.crv;
  if (typeof crv !== 'string' || !(crv in OKP_CURVES)) {
    throw new JwkError(
      ErrorCode.UNSUPPORTED_CURVE,
      `validate: OKP \`crv\` must be one of ${Object.keys(OKP_CURVES).join(' | ')}, got ${JSON.stringify(crv)}`,
    );
  }
  const size = OKP_KEY_BYTES[/** @type {keyof typeof OKP_KEY_BYTES} */ (crv)];
  _requireString(j, 'x');
  decodeMember(/** @type {string} */ (j.x), 'OKP.x', size);
  if (j.d !== undefined) {
    _requireString(j, 'd');
    decodeMember(/** @type {string} */ (j.d), 'OKP.d', size);
    return true;
  }
  return false;
}

/**
 * @param {Record<string, unknown>} j
 * @param {string} name
 */
function _requireString(j, name) {
  if (typeof j[name] !== 'string' || /** @type {string} */ (j[name]).length === 0) {
    throw new JwkError(
      ErrorCode.MISSING_REQUIRED_MEMBER,
      `validate: required string member \`${name}\` is missing or empty`,
    );
  }
}
