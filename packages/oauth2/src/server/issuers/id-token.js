/**
 * OIDC `id_token` signer (OpenID Connect Core §2). Distinct from the
 * access-token issuer strategy on purpose: an id_token is ALWAYS a signed
 * JWS regardless of whether access tokens are JWT or PASETO, so it can't
 * ride on {@link import('./jwt.js').jwtIssuer} / `pasetoIssuer`. This is a
 * thin, dedicated signer the server reaches for only when a request was
 * granted the `openid` scope.
 *
 * Standard claims are set here (`iss` / `sub` / `aud` / `iat` / `exp`),
 * plus the OIDC-specific `nonce`, `auth_time`, and `at_hash` when the
 * inputs are present. `at_hash` is computed with the same rule the RP side
 * verifies it by ({@link import('../../internal/id-token.js').tokenHash}).
 */
import { sign } from '@exortek/jwt';
import { parseDuration } from '@exortek/shared/duration';
import { isNonEmptyString, isNullish, isNumber, isObject } from '@exortek/shared/predicates';

import { ErrorCode, OAuth2Error } from '../../internal/errors.js';
import { requireNonEmptyString } from '../../internal/guards.js';
import { tokenHash } from '../../internal/id-token.js';

const DEFAULT_EXPIRES_IN = '10m';

/**
 * @typedef {Object} IdTokenSignerConfig
 * @property {import('node:crypto').KeyObject | string | Uint8Array} signingKey  private (asymmetric) signing key
 * @property {string} alg                    JWS alg, e.g. `'RS256'` / `'ES256'` / `'EdDSA'` (never `none`/HS*)
 * @property {string} [kid]                  `kid` header so a client picks the right JWKS key
 * @property {string | number} [expiresIn]   id_token lifetime (default `'10m'`)
 */

/**
 * @param {IdTokenSignerConfig} config
 * @returns {{ alg: string, sign: (input: IdTokenInput) => Promise<string> }}
 *
 * @typedef {Object} IdTokenInput
 * @property {string} subject        the authenticated resource owner → `sub`
 * @property {string} clientId       → `aud`
 * @property {string} issuer         the AS issuer identifier → `iss`
 * @property {string} [nonce]        the authorization-request `nonce` (replay guard)
 * @property {number} [authTime]     unix seconds of the authentication event → `auth_time`
 * @property {string} [accessToken]  present → bind it via `at_hash`
 */
export function createIdTokenSigner(config) {
  if (!isObject(config)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'oidc.idToken requires a config object');
  }
  const alg = requireNonEmptyString(config.alg, 'oidc.idToken.alg');
  if (isNullish(config.signingKey)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'oidc.idToken requires a signingKey');
  }
  const { signingKey, kid } = config;
  const expiresInSec = Math.floor(parseDuration(config.expiresIn ?? DEFAULT_EXPIRES_IN) / 1000);

  return {
    alg,
    /**
     * @param {IdTokenInput} input
     * @returns {Promise<string>}
     */
    async sign(input) {
      /** @type {Record<string, unknown>} */
      const claims = {};
      // The nonce binds the id_token to THIS authorization request; omit it
      // when the flow carried none (a non-OIDC-nonce client).
      if (isNonEmptyString(input.nonce)) {
        claims.nonce = input.nonce;
      }
      if (isNumber(input.authTime)) {
        claims.auth_time = input.authTime;
      }
      // at_hash binds the paired access token (OIDC Core §3.1.3.6).
      if (isNonEmptyString(input.accessToken)) {
        claims.at_hash = tokenHash(input.accessToken, alg);
      }
      return sign(claims, signingKey, {
        alg,
        issuer: input.issuer,
        subject: input.subject,
        audience: input.clientId,
        expiresIn: expiresInSec,
        ...(isNonEmptyString(kid) ? { kid } : {}),
      });
    },
  };
}
