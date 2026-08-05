/**
 * OpenID Connect `id_token` verification for the RP flow.
 *
 * The signature and the standard claims (`iss` / `aud` / `nonce` /
 * `exp` / `nbf` / `iat`) are verified by `@exortek/jwt` against keys
 * resolved from the provider's JWKS through `@exortek/jwks` — we do not
 * reimplement JWT verification. This module adds
 * the OIDC-specific checks `jwt.verify` does not cover:
 *
 *   - `azp` must equal our `client_id` when the token has multiple
 *     audiences (cross-client token confusion),
 *   - `at_hash` / `c_hash` bind the access token / authorization code to
 *     the id_token,
 *
 * and translates `@exortek/jwt` failures into this package's stable
 * {@link ErrorCode} surface.
 */
import { createHash } from 'node:crypto';

import { encode as base64urlEncode } from '@exortek/shared/base64url';
import { isArray, isNonEmptyString, isObject, isString } from '@exortek/shared/predicates';
import { verify as jwtVerify } from '@exortek/jwt';
import { createRemoteJWKS } from '@exortek/jwks';

import { ErrorCode, OAuth2Error } from './errors.js';

// The strict alg allowlist for provider id_tokens. `none` and the HS*
// (symmetric) family are excluded structurally — an id_token is signed
// with the provider's asymmetric key, never a shared secret, so RS/HS
// confusion is impossible to express here.
export const DEFAULT_ID_TOKEN_ALGS = ['RS256', 'ES256', 'PS256', 'RS384', 'ES384', 'RS512', 'ES512', 'EdDSA'];

/** Map an `@exortek/jwt` failure code onto our specific error code. */
const JWT_CODE_MAP = {
  INVALID_NONCE: ErrorCode.NONCE_MISMATCH,
  INVALID_AUDIENCE: ErrorCode.AUDIENCE_MISMATCH,
  INVALID_ISSUER: ErrorCode.ISSUER_MISMATCH,
};

/**
 * Build a cached JWKS resolver for a provider's `jwks_uri`. Thin wrapper
 * over `createRemoteJWKS` so the engine holds one resolver per provider
 * (TTL cache + kid-miss refetch survive key rotation).
 *
 * @param {string} jwksUri
 * @param {import('@exortek/jwks').RemoteJWKSOptions} [options]
 * @returns {(header: { kid: string, alg?: string }) => Promise<import('node:crypto').KeyObject>}
 */
export function createJwksResolver(jwksUri, options) {
  return createRemoteJWKS(jwksUri, options);
}

/**
 * @typedef {Object} VerifyIdTokenOptions
 * @property {(header: { kid: string, alg?: string }) => Promise<import('node:crypto').KeyObject>} jwks  key resolver (from {@link createJwksResolver})
 * @property {string} issuer          expected `iss` (exact match)
 * @property {string} clientId        expected `aud`
 * @property {string} [nonce]         expected `nonce` (OIDC replay guard)
 * @property {string|number} [clockTolerance]  leeway for exp/nbf/iat
 * @property {string[]} [algs]        signature alg allowlist
 * @property {string} [accessToken]   present → `at_hash` is enforced
 * @property {string} [code]          present → `c_hash` is enforced
 */

/**
 * Verify a provider `id_token` and return its claims.
 *
 * @param {string} idToken
 * @param {VerifyIdTokenOptions} options
 * @returns {Promise<{ claims: Record<string, unknown>, header: Record<string, unknown>, sub: string }>}
 */
export async function verifyIdToken(idToken, options) {
  const { jwks, issuer, clientId, nonce, clockTolerance, algs = DEFAULT_ID_TOKEN_ALGS, accessToken, code } = options;

  /** @type {{ header: Record<string, unknown>, payload: Record<string, unknown> }} */
  let result;
  try {
    result = await jwtVerify(idToken, jwks, {
      alg: algs,
      issuer,
      audience: clientId,
      nonce,
      clockTolerance,
    });
  } catch (err) {
    const mapped = isObject(err) && 'code' in err ? JWT_CODE_MAP[err.code] : undefined;
    throw new OAuth2Error(
      mapped ?? ErrorCode.ID_TOKEN_INVALID,
      `id_token verification failed: ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    );
  }

  const { header, payload } = result;

  // Multi-audience tokens must name us as the authorized party.
  if (isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== clientId) {
    throw new OAuth2Error(
      ErrorCode.AUDIENCE_MISMATCH,
      'id_token has multiple audiences and azp does not match the client_id',
    );
  }

  const alg = /** @type {string} */ (header.alg);
  if (isString(accessToken) && isString(payload.at_hash)) {
    if (tokenHash(accessToken, alg) !== payload.at_hash) {
      throw new OAuth2Error(ErrorCode.ID_TOKEN_INVALID, 'id_token at_hash does not match the access token');
    }
  }
  if (isString(code) && isString(payload.c_hash)) {
    if (tokenHash(code, alg) !== payload.c_hash) {
      throw new OAuth2Error(ErrorCode.ID_TOKEN_INVALID, 'id_token c_hash does not match the authorization code');
    }
  }

  if (!isNonEmptyString(payload.sub)) {
    throw new OAuth2Error(ErrorCode.ID_TOKEN_INVALID, 'id_token has no `sub` claim');
  }

  return { claims: payload, header, sub: payload.sub };
}

/**
 * OIDC hash-binding value (`at_hash` / `c_hash`): base64url of the
 * left-most half of the hash of the ASCII value, where the hash matches
 * the id_token's signing alg (…256 → SHA-256, …384 → SHA-384, …512 →
 * SHA-512). EdDSA uses SHA-512 (OIDC Core §3.1.3.6, Ed25519). Exported so
 * the authorization server's id_token signer computes `at_hash` with the
 * exact same rule the RP side verifies it by.
 *
 * @param {string} value
 * @param {string} alg
 * @returns {string}
 */
export function tokenHash(value, alg) {
  const bits = alg.endsWith('384') ? 384 : alg.endsWith('512') || alg === 'EdDSA' ? 512 : 256;
  const digest = createHash(`sha${bits}`).update(value, 'ascii').digest();
  return base64urlEncode(digest.subarray(0, digest.length / 2));
}
