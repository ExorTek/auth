/**
 * Export a `node:crypto` `KeyObject` into JWK or PEM form.
 *
 * `exportJWK` produces the RFC 7517 JSON structure; `exportPEM` returns
 * SPKI (public) or PKCS#8 (private) PEM. Both preserve `kid` / `use` /
 * `alg` / `key_ops` metadata when supplied via {@link ExportJWKOptions}.
 *
 * `toPublic` is the differentiator: strips every private / secret member
 * from a JWK object (no KeyObject roundtrip) so a JWKS endpoint can be
 * built from private material without leaking `d` / RSA CRT parameters.
 */

import { KeyObject } from 'node:crypto';

import { JwkError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {Object} ExportJWKOptions
 * @property {string} [kid]
 * @property {'sig' | 'enc'} [use]
 * @property {string} [alg]
 * @property {string[]} [key_ops]
 */

/**
 * KeyObject → JWK. For asymmetric public / private keys and for `oct`
 * secret keys alike. Decorator fields override anything Node put in
 * `asymmetricKeyDetails`.
 *
 * @param {KeyObject} key
 * @param {ExportJWKOptions} [options]
 * @returns {Promise<object>}
 */
export async function exportJWK(key, options) {
  if (!(key instanceof KeyObject)) {
    throw new JwkError(ErrorCode.INVALID_ARGUMENT, 'exportJWK: expected a KeyObject');
  }
  /** @type {Record<string, unknown>} */
  let jwk;
  try {
    jwk = /** @type {Record<string, unknown>} */ (key.export({ format: 'jwk' }));
  } catch (err) {
    throw new JwkError(
      ErrorCode.INVALID_KEY,
      `exportJWK: node:crypto refused the export — ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    );
  }
  const opts = options || {};
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
  return jwk;
}

/**
 * @typedef {'spki' | 'pkcs8'} PemExportFormat
 */

/**
 * KeyObject → PEM. Format defaults to SPKI for public keys and PKCS#8
 * for private keys — the sensible choice unless a specific interop
 * target demands otherwise.
 *
 * @param {KeyObject} key
 * @param {PemExportFormat} [format]
 * @returns {Promise<string>}
 */
export async function exportPEM(key, format) {
  if (!(key instanceof KeyObject)) {
    throw new JwkError(ErrorCode.INVALID_ARGUMENT, 'exportPEM: expected a KeyObject');
  }
  if (key.type === 'secret') {
    throw new JwkError(
      ErrorCode.INVALID_ARGUMENT,
      'exportPEM: symmetric (secret) keys have no PEM representation — use exportJWK',
    );
  }
  const chosen = format ?? (key.type === 'private' ? 'pkcs8' : 'spki');
  if (chosen !== 'spki' && chosen !== 'pkcs8') {
    throw new JwkError(
      ErrorCode.INVALID_FORMAT,
      `exportPEM: unsupported format ${JSON.stringify(chosen)} — expected "spki" | "pkcs8"`,
    );
  }
  if (chosen === 'pkcs8' && key.type !== 'private') {
    throw new JwkError(ErrorCode.INVALID_ARGUMENT, 'exportPEM: pkcs8 requires a private KeyObject');
  }
  if (chosen === 'spki' && key.type === 'private') {
    // Emitting a public SPKI from a private key would silently reveal
    // only the public projection — allow, but be explicit about intent
    // by refusing here; callers should extract the public key first via
    // `createPublicKey(privateKey)`.
    throw new JwkError(
      ErrorCode.INVALID_ARGUMENT,
      'exportPEM: passing a private KeyObject with format="spki" is ambiguous — extract the public key first with createPublicKey(privateKey)',
    );
  }
  const out = key.export({ format: 'pem', type: chosen });
  return typeof out === 'string' ? out : out.toString('utf8');
}

/**
 * Strip every private / secret member from a JWK, returning a defensive
 * shallow copy that is safe to publish (e.g. via a JWKS endpoint).
 *
 * Not exposed by `jose`: callers there have to remember which kty stores
 * the secret in which member.
 *
 * @param {object} jwk
 * @returns {object}
 */
export function toPublic(jwk) {
  if (jwk == null || typeof jwk !== 'object') {
    throw new JwkError(ErrorCode.INVALID_ARGUMENT, 'toPublic: expected a JWK object');
  }
  const j = /** @type {Record<string, unknown>} */ (jwk);
  if (j.kty === 'oct') {
    throw new JwkError(
      ErrorCode.INVALID_ARGUMENT,
      'toPublic: `oct` JWKs are symmetric — they have no public projection',
    );
  }
  const clone = { ...j };
  delete clone.d;
  if (j.kty === 'RSA') {
    delete clone.p;
    delete clone.q;
    delete clone.dp;
    delete clone.dq;
    delete clone.qi;
    delete clone.oth;
  }
  return clone;
}
