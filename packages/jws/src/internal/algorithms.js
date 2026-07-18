/**
 * Algorithm registry — RFC 7518 §3, RFC 8037 §3, RFC 8812 §3.
 * Composed from the shared factories; this file only curates the table
 * and translates lookup failures into typed `JwsError`s.
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

import { hmac, rsaPkcs1, rsaPss, ecdsa, eddsa, createRegistry } from '@exortek/shared/algorithms';
import { JwsError, ErrorCode } from './errors.js';

/** @typedef {import('@exortek/shared/algorithms').AlgDescriptor} AlgDescriptor */

const registry = createRegistry({
  HS256: hmac('HS256', 'sha256'),
  HS384: hmac('HS384', 'sha384'),
  HS512: hmac('HS512', 'sha512'),

  RS256: rsaPkcs1('RS256', 'sha256'),
  RS384: rsaPkcs1('RS384', 'sha384'),
  RS512: rsaPkcs1('RS512', 'sha512'),

  PS256: rsaPss('PS256', 'sha256'),
  PS384: rsaPss('PS384', 'sha384'),
  PS512: rsaPss('PS512', 'sha512'),

  ES256: ecdsa('ES256', 'sha256', 'P-256'),
  ES384: ecdsa('ES384', 'sha384', 'P-384'),
  ES512: ecdsa('ES512', 'sha512', 'P-521'),
  ES256K: ecdsa('ES256K', 'sha256', 'secp256k1'),

  EdDSA: eddsa(),
});

/** Every JOSE algorithm identifier this package supports. */
export const SUPPORTED = registry.SUPPORTED;

/**
 * Look up an algorithm's descriptor. Throws
 * {@link ErrorCode.UNSUPPORTED_ALGORITHM} for anything not in the table,
 * including the placeholder `'none'` alg.
 *
 * @param {string} alg
 * @returns {AlgDescriptor}
 */
export function lookup(alg) {
  try {
    return registry.lookup(alg);
  } catch (err) {
    throw new JwsError(ErrorCode.UNSUPPORTED_ALGORITHM, err instanceof Error ? err.message : String(err));
  }
}
