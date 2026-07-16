/**
 * Generate a fresh JWK — RFC 7517 / RFC 7518 §6 / RFC 8037.
 *
 * Emits **both** the public and private JWK for asymmetric kty. For
 * `oct` only a single (symmetric) JWK is produced (both projections
 * reference the same object because `oct` has no public/private split).
 *
 * `kid`, `use`, `alg`, and `key_ops` are forwarded verbatim when supplied.
 */

import { generateKeyPair as _generateKeyPair, randomBytes as _randomBytes } from 'node:crypto';
import { promisify } from 'node:util';

import { JwkError, ErrorCode } from './internal/errors.js';
import { EC_CURVES, OKP_CURVES } from './internal/curves.js';
import { encode as b64uEncode } from './internal/base64url.js';

const generateKeyPair = promisify(_generateKeyPair);
const randomBytes = promisify(_randomBytes);

/**
 * @typedef {'EC' | 'RSA' | 'OKP' | 'oct'} Kty
 * @typedef {'P-256' | 'P-384' | 'P-521' | 'secp256k1'} EcCurve
 * @typedef {'Ed25519' | 'Ed448' | 'X25519' | 'X448'} OkpCurve
 */

/**
 * @typedef {Object} GenerateOptionsCommon
 * @property {string} [kid]
 * @property {'sig' | 'enc'} [use]
 * @property {string} [alg]
 * @property {string[]} [key_ops]
 */

/**
 * @typedef {GenerateOptionsCommon & { curve?: EcCurve }} GenerateOptionsEC
 * @typedef {GenerateOptionsCommon & { modulusLength?: number, publicExponent?: number }} GenerateOptionsRSA
 * @typedef {GenerateOptionsCommon & { curve?: OkpCurve }} GenerateOptionsOKP
 * @typedef {GenerateOptionsCommon & { bits?: number }} GenerateOptionsOct
 */

/**
 * @typedef {Object} GeneratedKeyPair
 * @property {object} publicJwk    public projection (asymmetric); equals `privateJwk` for `oct`
 * @property {object} privateJwk   private JWK (contains `d`, or `k` for `oct`)
 */

/**
 * Generate a JWK for the requested `kty`.
 *
 * @param {Kty} kty
 * @param {GenerateOptionsEC | GenerateOptionsRSA | GenerateOptionsOKP | GenerateOptionsOct} [options]
 * @returns {Promise<GeneratedKeyPair>}
 */
export async function generate(kty, options) {
  const opts = options || {};
  switch (kty) {
    case 'EC':
      return _generateEC(/** @type {GenerateOptionsEC} */ (opts));
    case 'RSA':
      return _generateRSA(/** @type {GenerateOptionsRSA} */ (opts));
    case 'OKP':
      return _generateOKP(/** @type {GenerateOptionsOKP} */ (opts));
    case 'oct':
      return _generateOct(/** @type {GenerateOptionsOct} */ (opts));
    default:
      throw new JwkError(
        ErrorCode.UNSUPPORTED_KTY,
        `generate: unsupported kty ${JSON.stringify(kty)} — expected one of "EC", "RSA", "OKP", "oct".`,
      );
  }
}

/** @param {GenerateOptionsEC} opts */
async function _generateEC(opts) {
  const curve = opts.curve || 'P-256';
  const namedCurve = EC_CURVES[curve];
  if (!namedCurve) {
    throw new JwkError(
      ErrorCode.UNSUPPORTED_CURVE,
      `generate(EC): unsupported curve ${JSON.stringify(curve)} — expected one of ${Object.keys(EC_CURVES).join(', ')}`,
    );
  }
  const { publicKey, privateKey } = await generateKeyPair('ec', { namedCurve });
  return _keyPairToJwk(publicKey, privateKey, opts);
}

/** @param {GenerateOptionsRSA} opts */
async function _generateRSA(opts) {
  const modulusLength = opts.modulusLength ?? 2048;
  if (typeof modulusLength !== 'number' || modulusLength < 2048 || modulusLength % 8 !== 0) {
    throw new JwkError(
      ErrorCode.INVALID_ARGUMENT,
      `generate(RSA): modulusLength must be a multiple of 8 and >= 2048, got ${modulusLength}`,
    );
  }
  const publicExponent = opts.publicExponent ?? 0x10001;
  const { publicKey, privateKey } = await generateKeyPair('rsa', {
    modulusLength,
    publicExponent,
  });
  return _keyPairToJwk(publicKey, privateKey, opts);
}

/** @param {GenerateOptionsOKP} opts */
async function _generateOKP(opts) {
  const curve = opts.curve || 'Ed25519';
  const nodeType = OKP_CURVES[curve];
  if (!nodeType) {
    throw new JwkError(
      ErrorCode.UNSUPPORTED_CURVE,
      `generate(OKP): unsupported curve ${JSON.stringify(curve)} — expected one of ${Object.keys(OKP_CURVES).join(', ')}`,
    );
  }
  const { publicKey, privateKey } = await generateKeyPair(nodeType);
  return _keyPairToJwk(publicKey, privateKey, opts);
}

/** @param {GenerateOptionsOct} opts */
async function _generateOct(opts) {
  const bits = opts.bits ?? 256;
  if (typeof bits !== 'number' || bits < 128 || bits % 8 !== 0) {
    throw new JwkError(
      ErrorCode.INVALID_ARGUMENT,
      `generate(oct): bits must be a multiple of 8 and >= 128, got ${bits}`,
    );
  }
  const bytes = await randomBytes(bits / 8);
  /** @type {Record<string, unknown>} */
  const jwk = { kty: 'oct', k: b64uEncode(bytes) };
  _decorate(jwk, opts);
  return { publicJwk: jwk, privateJwk: jwk };
}

/**
 * @param {import('node:crypto').KeyObject} publicKey
 * @param {import('node:crypto').KeyObject} privateKey
 * @param {GenerateOptionsCommon} opts
 * @returns {GeneratedKeyPair}
 */
function _keyPairToJwk(publicKey, privateKey, opts) {
  const publicJwk = /** @type {Record<string, unknown>} */ (publicKey.export({ format: 'jwk' }));
  const privateJwk = /** @type {Record<string, unknown>} */ (privateKey.export({ format: 'jwk' }));
  _decorate(publicJwk, opts);
  _decorate(privateJwk, opts);
  return { publicJwk, privateJwk };
}

/**
 * @param {Record<string, unknown>} jwk
 * @param {GenerateOptionsCommon} opts
 */
function _decorate(jwk, opts) {
  if (opts.kid !== undefined) {
    jwk.kid = opts.kid;
  }
  if (opts.use !== undefined) {
    jwk.use = opts.use;
  }
  if (opts.alg !== undefined) {
    jwk.alg = opts.alg;
  }
  if (opts.key_ops !== undefined) {
    jwk.key_ops = [...opts.key_ops];
  }
}
