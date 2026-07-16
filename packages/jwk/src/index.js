/**
 * `@exortek/jwk` — JSON Web Key (RFC 7517), thumbprint (RFC 7638 / RFC
 * 9278), OKP support (RFC 8037). Zero-dependency, `node:crypto` only.
 *
 * Two import styles are exposed:
 *
 * ```js
 * // 1. Namespace — mirrors ARCHITECTURE.md example
 * import { jwk } from '@exortek/jwk'
 * await jwk.generate('EC', { curve: 'P-256' })
 *
 * // 2. Named — smaller bundle, tree-shakeable
 * import { generate, importJWK, thumbprint } from '@exortek/jwk'
 * ```
 */

import { generate } from './generate.js';
import { importJWK, importPEM } from './import.js';
import { exportJWK, exportPEM, toPublic } from './export.js';
import { thumbprint, thumbprintURI, matches } from './thumbprint.js';
import { validate, isValid } from './validate.js';
import { JwkError, ErrorCode } from './internal/errors.js';

export { generate, importJWK, importPEM, exportJWK, exportPEM, toPublic };
export { thumbprint, thumbprintURI, matches };
export { validate, isValid };
export { JwkError, ErrorCode };

/**
 * `jwk.export(key, { format })` — bundled dispatcher used by the
 * namespace API. Named exports (`exportJWK`, `exportPEM`) remain
 * single-purpose; the namespace form matches the ARCHITECTURE.md example
 * where `format` selects the output shape.
 *
 *   - `format: 'jwk'` (default) → {@link exportJWK}, options forwarded verbatim
 *   - `format: 'pem'`           → {@link exportPEM}, `pemType` selects SPKI vs PKCS#8
 *
 * @param {import('node:crypto').KeyObject} key
 * @param {import('./export.js').ExportJWKOptions & { format?: 'jwk' | 'pem', pemType?: import('./export.js').PemExportFormat }} [options]
 * @returns {Promise<object | string>}
 */
async function _exportDispatch(key, options) {
  const opts = options || {};
  const format = opts.format ?? 'jwk';
  if (format === 'jwk') {
    const { format: _f, pemType: _p, ...rest } = /** @type {any} */ (opts);
    return exportJWK(key, rest);
  }
  if (format === 'pem') {
    return exportPEM(key, opts.pemType);
  }
  throw new JwkError(
    ErrorCode.INVALID_FORMAT,
    `jwk.export: unsupported format ${JSON.stringify(format)} — expected "jwk" | "pem"`,
  );
}

/**
 * Bundled namespace matching the ARCHITECTURE example.
 *
 * `jwk.import` / `jwk.export` are property-access aliases for
 * {@link importJWK} / {@link _exportDispatch} — inside an object literal
 * the reserved-word restriction does not apply.
 */
export const jwk = Object.freeze({
  generate,
  import: importJWK,
  importPEM,
  export: _exportDispatch,
  exportPEM,
  toPublic,
  thumbprint,
  thumbprintURI,
  matches,
  validate,
  isValid,
});

/**
 * @typedef {import('./generate.js').Kty} Kty
 * @typedef {import('./generate.js').EcCurve} EcCurve
 * @typedef {import('./generate.js').OkpCurve} OkpCurve
 * @typedef {import('./generate.js').GeneratedKeyPair} GeneratedKeyPair
 * @typedef {import('./thumbprint.js').ThumbprintDigest} ThumbprintDigest
 * @typedef {import('./validate.js').ValidateOptions} ValidateOptions
 * @typedef {import('./import.js').ImportJWKOptions} ImportJWKOptions
 * @typedef {import('./import.js').PemFormat} PemFormat
 * @typedef {import('./export.js').ExportJWKOptions} ExportJWKOptions
 * @typedef {import('./export.js').PemExportFormat} PemExportFormat
 */
