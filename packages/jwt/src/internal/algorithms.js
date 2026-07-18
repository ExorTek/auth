/**
 * Algorithm registry — RFC 7518 §3, RFC 8037 §3, RFC 8812 §3.
 *
 * Standalone per package policy — code kept in sync with `@exortek/jws`
 * to avoid a runtime cross-`@exortek` dependency. Each entry carries
 * everything `sign` / `verify` need to route to the right `node:crypto`
 * primitive without the surface files having to branch by alg
 * themselves.
 *
 *   - HMAC (RFC 7518 §3.2) — HS256 / HS384 / HS512
 *   - RSA PKCS#1 v1.5 (§3.3) — RS256 / RS384 / RS512
 *   - RSA-PSS (§3.5) — PS256 / PS384 / PS512
 *   - ECDSA (§3.4) — ES256 / ES384 / ES512
 *   - ECDSA secp256k1 (RFC 8812) — ES256K
 *   - EdDSA (RFC 8037) — Ed25519 / Ed448
 *
 * `alg: 'none'` is deliberately **not** in the table. `lookup('none')`
 * throws {@link ErrorCode.UNSUPPORTED_ALGORITHM}; the sign / verify
 * surfaces have a dedicated {@link ErrorCode.ALGORITHM_NONE_FORBIDDEN}
 * fast-path so the user's diagnostic is actionable.
 */

import crypto, { constants, createHmac, sign as _sign, verify as _verify } from 'node:crypto';

import { JwtError, ErrorCode } from './errors.js';
import { derToRaw, rawToDer, EC_COORD_BYTES } from './ecdsa.js';

/** HMAC minimum secret sizes per RFC 7518 §3.2 — key must be ≥ hash output. */
const HMAC_MIN_BYTES = { HS256: 32, HS384: 48, HS512: 64 };

/**
 * @typedef {'HMAC' | 'RSA' | 'RSA-PSS' | 'ECDSA' | 'EdDSA'} Family
 *
 * @typedef {Object} AlgDescriptor
 * @property {string} alg
 * @property {Family} family
 * @property {string} [hash]                    Node digest name (`sha256` etc). EdDSA has none.
 * @property {'oct' | 'RSA' | 'EC' | 'OKP'} kty  Expected JWK `kty`.
 * @property {string} [curve]                    For ECDSA — expected JWK `crv`.
 * @property {number} [hmacMinBytes]             For HMAC — RFC 7518 §3.2 minimum.
 * @property {number} [rsaSaltLength]            For RSA-PSS — matches hash output size.
 * @property {(key: import('node:crypto').KeyObject, message: Buffer) => Promise<Buffer>} sign
 * @property {(key: import('node:crypto').KeyObject, message: Buffer, signature: Buffer) => Promise<boolean>} verify
 */

/** @type {Record<string, AlgDescriptor>} */
const TABLE = Object.freeze({
  HS256: _hmac('HS256', 'sha256'),
  HS384: _hmac('HS384', 'sha384'),
  HS512: _hmac('HS512', 'sha512'),

  RS256: _rsaPkcs1('RS256', 'sha256'),
  RS384: _rsaPkcs1('RS384', 'sha384'),
  RS512: _rsaPkcs1('RS512', 'sha512'),

  PS256: _rsaPss('PS256', 'sha256'),
  PS384: _rsaPss('PS384', 'sha384'),
  PS512: _rsaPss('PS512', 'sha512'),

  ES256: _ecdsa('ES256', 'sha256', 'P-256'),
  ES384: _ecdsa('ES384', 'sha384', 'P-384'),
  ES512: _ecdsa('ES512', 'sha512', 'P-521'),
  ES256K: _ecdsa('ES256K', 'sha256', 'secp256k1'),

  EdDSA: _eddsa(),
});

/** Every JOSE algorithm identifier this package supports. */
export const SUPPORTED = Object.freeze(Object.keys(TABLE));

/**
 * Look up an algorithm's descriptor. Throws
 * {@link ErrorCode.UNSUPPORTED_ALGORITHM} for anything not in the table,
 * including the placeholder `'none'` alg.
 *
 * @param {string} alg
 * @returns {AlgDescriptor}
 */
export function lookup(alg) {
  const entry = TABLE[/** @type {keyof typeof TABLE} */ (alg)];
  if (!entry) {
    throw new JwtError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `algorithms.lookup: unsupported alg ${JSON.stringify(alg)}. Supported: ${SUPPORTED.join(', ')}`,
    );
  }
  return entry;
}

function _hmac(alg, hash) {
  return {
    alg,
    family: 'HMAC',
    hash,
    kty: 'oct',
    hmacMinBytes: HMAC_MIN_BYTES[/** @type {keyof typeof HMAC_MIN_BYTES} */ (alg)],
    async sign(key, message) {
      const raw = key.export();
      return createHmac(hash, raw).update(message).digest();
    },
    async verify(key, message, signature) {
      const raw = key.export();
      const expected = createHmac(hash, raw).update(message).digest();
      if (signature.length !== expected.length) {
        return false;
      }
      return crypto.timingSafeEqual(signature, expected);
    },
  };
}

function _rsaPkcs1(alg, hash) {
  return {
    alg,
    family: 'RSA',
    hash,
    kty: 'RSA',
    async sign(key, message) {
      return _sign(hash, message, { key, padding: constants.RSA_PKCS1_PADDING });
    },
    async verify(key, message, signature) {
      return _verify(hash, message, { key, padding: constants.RSA_PKCS1_PADDING }, signature);
    },
  };
}

function _rsaPss(alg, hash) {
  const saltLength = /^sha(\d+)$/.exec(hash)?.[1];
  const rsaSaltLength = saltLength ? Number(saltLength) / 8 : 32;
  return {
    alg,
    family: 'RSA-PSS',
    hash,
    kty: 'RSA',
    rsaSaltLength,
    async sign(key, message) {
      return _sign(hash, message, {
        key,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: rsaSaltLength,
      });
    },
    async verify(key, message, signature) {
      return _verify(
        hash,
        message,
        { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: rsaSaltLength },
        signature,
      );
    },
  };
}

function _ecdsa(alg, hash, curve) {
  const size = EC_COORD_BYTES[/** @type {keyof typeof EC_COORD_BYTES} */ (curve)];
  return {
    alg,
    family: 'ECDSA',
    hash,
    kty: 'EC',
    curve,
    async sign(key, message) {
      const der = _sign(hash, message, key);
      return derToRaw(der, curve);
    },
    async verify(key, message, signature) {
      if (signature.length !== size * 2) {
        return false;
      }
      const der = rawToDer(signature, curve);
      return _verify(hash, message, key, der);
    },
  };
}

function _eddsa() {
  return {
    alg: 'EdDSA',
    family: 'EdDSA',
    kty: 'OKP',
    async sign(key, message) {
      return _sign(null, message, key);
    },
    async verify(key, message, signature) {
      return _verify(null, message, key, signature);
    },
  };
}
