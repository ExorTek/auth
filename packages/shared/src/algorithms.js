/**
 * Signing / verification algorithm primitive factories + a small
 * `createRegistry` helper. Consumers curate their own `TABLE` from
 * these factories so different packages (jwt / jws / jwks / jwe) can
 * ship different algorithm subsets — one can drop `ES512` or add
 * `EdDSA-Ed448` without touching the shared file.
 *
 * Covered specs:
 *
 *   - HMAC (RFC 7518 §3.2) — `hmac(alg, hash)`
 *   - RSA PKCS#1 v1.5 (§3.3) — `rsaPkcs1(alg, hash)`
 *   - RSA-PSS (§3.5) — `rsaPss(alg, hash)`
 *   - ECDSA (§3.4 + RFC 8812 for secp256k1) — `ecdsa(alg, hash, curve)`
 *   - EdDSA (RFC 8037) — `eddsa()`
 *
 * `alg: 'none'` is deliberately NOT a factory. Every consumer surfaces
 * its own `ALGORITHM_NONE_FORBIDDEN` error code in its sign / verify
 * fast-path — the shared layer never has to think about it.
 *
 * @example
 *   // jwt/internal/algorithms.js
 *   import { hmac, rsaPkcs1, rsaPss, ecdsa, eddsa, createRegistry } from
 *     '@exortek/shared/algorithms';
 *   import { JwtError, ErrorCode } from './errors.js';
 *
 *   const registry = createRegistry({
 *     HS256:  hmac('HS256', 'sha256'),
 *     HS384:  hmac('HS384', 'sha384'),
 *     HS512:  hmac('HS512', 'sha512'),
 *     RS256:  rsaPkcs1('RS256', 'sha256'),
 *     ES256:  ecdsa('ES256', 'sha256', 'P-256'),
 *     EdDSA:  eddsa(),
 *   });
 *
 *   export const SUPPORTED = registry.SUPPORTED;
 *   export function lookup(alg) {
 *     try { return registry.lookup(alg); }
 *     catch (e) { throw new JwtError(ErrorCode.UNSUPPORTED_ALGORITHM, e.message); }
 *   }
 */

import crypto, { constants, createHmac, sign as _sign, verify as _verify } from 'node:crypto';

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

/**
 * Build a lookup registry over a caller-curated algorithm set.
 *
 * @param {Record<string, AlgDescriptor>} table
 * @returns {{ SUPPORTED: readonly string[], lookup(alg: string): AlgDescriptor }}
 */
export function createRegistry(table) {
  const frozen = Object.freeze({ ...table });
  const supported = Object.freeze(Object.keys(frozen));
  return {
    SUPPORTED: supported,
    lookup(alg) {
      const entry = frozen[/** @type {keyof typeof frozen} */ (alg)];
      if (!entry) {
        throw new Error(
          `algorithms.lookup: unsupported alg ${JSON.stringify(alg)}. Supported: ${supported.join(', ')}`,
        );
      }
      return entry;
    },
  };
}

/**
 * HMAC entry factory.
 *
 * @param {string} alg   e.g. `'HS256'`
 * @param {string} hash  Node digest name — `'sha256' | 'sha384' | 'sha512'`
 * @returns {AlgDescriptor}
 */
export function hmac(alg, hash) {
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

/**
 * RSA PKCS#1 v1.5 entry factory (RS256/384/512).
 *
 * @param {string} alg
 * @param {string} hash
 * @returns {AlgDescriptor}
 */
export function rsaPkcs1(alg, hash) {
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

/**
 * RSA-PSS entry factory (PS256/384/512). Salt length matches the hash
 * output size (RFC 7518 §3.5).
 *
 * @param {string} alg
 * @param {string} hash
 * @returns {AlgDescriptor}
 */
export function rsaPss(alg, hash) {
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

/**
 * ECDSA entry factory. Wire signature is raw R‖S per RFC 7515 §3.4;
 * we convert on the way in and out through `signing/ecdsa`.
 *
 * @param {string} alg
 * @param {string} hash
 * @param {string} curve  JWK `crv` value — `'P-256' | 'P-384' | 'P-521' | 'secp256k1'`
 * @returns {AlgDescriptor}
 */
export function ecdsa(alg, hash, curve) {
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

/**
 * EdDSA entry factory (RFC 8037). No hash parameter — Ed25519 / Ed448
 * mix the message in via their own PRF (SHA-512 / SHAKE256).
 *
 * @returns {AlgDescriptor}
 */
export function eddsa() {
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
