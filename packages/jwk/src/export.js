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

import { array, object, oneOf, optional, string } from '@exortek/shared/validate';
import { isString } from '@exortek/shared/predicates';

import { JwkError, ErrorCode } from './internal/errors.js';
import { assertObject, invalidArgument, parse } from './internal/guards.js';

const ExportJWKOptionsSchema = object({
  kid: optional(string()),
  use: optional(oneOf(['sig', 'enc'])),
  alg: optional(string()),
  key_ops: optional(array(string())),
});

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
    throw invalidArgument('exportJWK.key must be a KeyObject');
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
  const opts = /** @type {ExportJWKOptions} */ (parse(ExportJWKOptionsSchema, options || {}, 'exportJWK.options'));
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
    throw invalidArgument('exportPEM.key must be a KeyObject');
  }
  if (key.type === 'secret') {
    throw invalidArgument('exportPEM.key: symmetric (secret) keys have no PEM representation — use exportJWK');
  }
  const chosen = format ?? (key.type === 'private' ? 'pkcs8' : 'spki');
  if (chosen !== 'spki' && chosen !== 'pkcs8') {
    throw new JwkError(
      ErrorCode.INVALID_FORMAT,
      `exportPEM: unsupported format ${JSON.stringify(chosen)} — expected "spki" | "pkcs8"`,
    );
  }
  if (chosen === 'pkcs8' && key.type !== 'private') {
    throw invalidArgument('exportPEM.key: pkcs8 requires a private KeyObject');
  }
  if (chosen === 'spki' && key.type === 'private') {
    // Emitting a public SPKI from a private key would silently reveal
    // only the public projection — allow, but be explicit about intent
    // by refusing here; callers should extract the public key first via
    // `createPublicKey(privateKey)`.
    throw invalidArgument(
      'exportPEM.key: passing a private KeyObject with format="spki" is ambiguous — extract the public key first with createPublicKey(privateKey)',
    );
  }
  const out = key.export({ format: 'pem', type: chosen });
  return isString(out) ? out : out.toString('utf8');
}

/**
 * Strip every private / secret member from a JWK, returning a defensive
 * shallow copy that is safe to publish (e.g. via a JWKS endpoint).
 *
 * Convenience over hand-stripping — callers don't have to remember
 * which `kty` stores the secret material in which member.
 *
 * @param {object} jwk
 * @returns {object}
 */
export function toPublic(jwk) {
  assertObject(jwk, 'toPublic.jwk');
  const j = /** @type {Record<string, unknown>} */ (jwk);
  if (j.kty === 'oct') {
    throw invalidArgument('toPublic.jwk: `oct` JWKs are symmetric — they have no public projection');
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
