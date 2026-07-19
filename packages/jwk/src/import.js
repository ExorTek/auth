/**
 * Import a JWK (or PEM/DER) into a `node:crypto` `KeyObject` — the shape
 * downstream libraries (`jws`, `jwt`, `jwe`) expect.
 *
 * `importJWK` validates the JWK first (see {@link ./validate.js}) then
 * hands it to `createPrivateKey` / `createPublicKey` / `createSecretKey`
 * with the JWK decoded per RFC 7517.
 */

import { createPrivateKey, createPublicKey, createSecretKey, X509Certificate } from 'node:crypto';

import { JwkError, ErrorCode } from './internal/errors.js';
import { decode as b64uDecode } from './internal/base64url.js';
import { invalidArgument } from './internal/guards.js';
import { validate } from './validate.js';

/** @typedef {import('node:crypto').KeyObject} KeyObject */

/**
 * @typedef {Object} ImportJWKOptions
 * @property {string} [alg] intended JOSE algorithm identifier — currently informational (Node ignores it in key import)
 */

/**
 * Convert a JWK into a `KeyObject`. JWKs with `d` (or `k` for `oct`)
 * yield a private / secret KeyObject; public JWKs yield a public one.
 *
 * @param {object} jwk
 * @param {ImportJWKOptions} [_options]
 * @returns {Promise<KeyObject>}
 */
export async function importJWK(jwk, _options) {
  const v = /** @type {Record<string, unknown>} */ (validate(jwk));
  try {
    if (v.kty === 'oct') {
      return createSecretKey(b64uDecode(/** @type {string} */ (v.k)));
    }
    const hasPrivate = v.d !== undefined;
    return hasPrivate
      ? createPrivateKey({ key: /** @type {any} */ (v), format: 'jwk' })
      : createPublicKey({ key: /** @type {any} */ (v), format: 'jwk' });
  } catch (err) {
    throw new JwkError(
      ErrorCode.INVALID_KEY,
      `importJWK: node:crypto rejected the JWK — ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    );
  }
}

/**
 * @typedef {'spki' | 'pkcs8' | 'x509'} PemFormat
 */

/**
 * Import a PEM- or DER-encoded key.
 *
 *   - `'spki'`  → public key (SubjectPublicKeyInfo)
 *   - `'pkcs8'` → private key (PrivateKeyInfo)
 *   - `'x509'`  → public key extracted from an X.509 certificate
 *
 * When `pemOrDer` is a `Buffer`, the input is treated as DER; strings
 * are PEM.
 *
 * @param {string | Buffer} pemOrDer
 * @param {PemFormat} [format='spki']
 * @returns {Promise<KeyObject>}
 */
export async function importPEM(pemOrDer, format = 'spki') {
  if (typeof pemOrDer !== 'string' && !Buffer.isBuffer(pemOrDer)) {
    throw invalidArgument('importPEM.pemOrDer must be a PEM string or DER Buffer');
  }
  const inputFormat = typeof pemOrDer === 'string' ? 'pem' : 'der';
  try {
    switch (format) {
      case 'x509': {
        const cert = new X509Certificate(pemOrDer);
        return cert.publicKey;
      }
      case 'pkcs8':
        return createPrivateKey({ key: pemOrDer, format: inputFormat, type: 'pkcs8' });
      case 'spki':
        return createPublicKey({ key: pemOrDer, format: inputFormat, type: 'spki' });
      default:
        throw new JwkError(
          ErrorCode.INVALID_FORMAT,
          `importPEM: unsupported format ${JSON.stringify(format)} — expected "spki" | "pkcs8" | "x509"`,
        );
    }
  } catch (err) {
    if (err instanceof JwkError) {
      throw err;
    }
    throw new JwkError(
      ErrorCode.INVALID_KEY,
      `importPEM(${format}): node:crypto rejected the input — ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    );
  }
}
