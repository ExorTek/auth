/**
 * JWT access-token issuer — the default, blessed backend (PLAN: JWT
 * profile RFC 9068). Signs `typ: "at+jwt"` access tokens through
 * `@exortek/jwt` and verifies them back for introspection. Refresh
 * tokens are NOT JWTs — they are opaque and live in the refresh store;
 * this issuer only mints/validates the access token.
 *
 * An issuer is a strategy with a uniform contract so `createServer` is
 * backend-agnostic:
 *   issue(grant, ctx)  → { accessToken, tokenType, expiresIn, jti }
 *   introspect(token)  → { active, claims } (verifies signature + exp)
 * `@exortek/paseto` provides the same contract via `pasetoIssuer`.
 */
import { sign, verify, JwtError } from '@exortek/jwt';
import { parseDuration } from '@exortek/shared/duration';
import { isNonEmptyString, isObject } from '@exortek/shared/predicates';

import { ErrorCode, OAuth2Error } from '../../internal/errors.js';
import { requireNonEmptyString } from '../../internal/guards.js';

const DEFAULT_EXPIRES_IN = '10m';

/**
 * @typedef {Object} JwtIssuerConfig
 * @property {import('node:crypto').KeyObject | string | Uint8Array} signingKey   private (asymmetric) or shared (HMAC) key
 * @property {import('node:crypto').KeyObject | string | Uint8Array} [verificationKey]  public key for introspection; defaults to `signingKey` (HMAC)
 * @property {string} alg                                                         JWS alg, e.g. `'RS256'` / `'ES256'` / `'EdDSA'`
 * @property {string | number} [expiresIn]                                        access-token lifetime (default `'10m'`)
 * @property {string} [kid]                                                        `kid` header, so a resource server can pick the key
 *
 * @typedef {Object} GrantContext
 * @property {string} issuer                    the AS issuer identifier (→ `iss`)
 *
 * @typedef {Object} AccessGrant
 * @property {string} subject                   resource owner (or client id for client_credentials) → `sub`
 * @property {string} clientId                  → `client_id`
 * @property {string[]} [scope]                 → space-delimited `scope`
 * @property {string | string[]} [audience]     resource indicator(s) (RFC 8707) → `aud`; falls back to `clientId`
 * @property {string} [dpopJkt]                 DPoP key thumbprint → `cnf.jkt` (RFC 9449)
 * @property {Record<string, unknown>} [extra]  additional claims (e.g. `authorization_details`)
 */

/**
 * @param {JwtIssuerConfig} config
 */
export function jwtIssuer(config) {
  if (!isObject(config)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'jwtIssuer requires a config object');
  }
  requireNonEmptyString(config.alg, 'jwtIssuer.alg');
  if (config.signingKey === undefined || config.signingKey === null) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'jwtIssuer requires a signingKey');
  }
  const { signingKey, alg, kid } = config;
  const verificationKey = config.verificationKey ?? signingKey;
  const expiresInMs = parseDuration(config.expiresIn ?? DEFAULT_EXPIRES_IN);
  const expiresInSec = Math.floor(expiresInMs / 1000);

  return {
    /**
     * Mint an RFC 9068 JWT access token.
     *
     * @param {AccessGrant} grant
     * @param {GrantContext} ctx
     * @returns {Promise<{ accessToken: string, tokenType: string, expiresIn: number, jti: string }>}
     */
    async issue(grant, ctx) {
      // RFC 9068 §3 mandates iss, exp, aud, sub, client_id, iat, jti.
      /** @type {Record<string, unknown>} */
      const claims = {
        client_id: grant.clientId,
        ...(isObject(grant.extra) ? grant.extra : {}),
      };
      if (Array.isArray(grant.scope) && grant.scope.length > 0) {
        claims.scope = grant.scope.join(' ');
      }
      const confirmation = resolveConfirmation(grant);
      if (confirmation) {
        // Sender-constrain the token: `cnf.jkt` for DPoP (RFC 9449 §6) or
        // `cnf.x5t#S256` for a certificate-bound token (RFC 8705 §3).
        claims.cnf = confirmation;
      }

      const audience = resolveAudience(grant);
      const token = await sign(claims, signingKey, {
        alg,
        typ: 'at+jwt',
        issuer: ctx.issuer,
        subject: grant.subject,
        audience,
        expiresIn: expiresInSec,
        jwtId: true,
        ...(isNonEmptyString(kid) ? { kid } : {}),
        returnMetadata: true,
      });

      return {
        accessToken: token.token,
        // DPoP-bound tokens use the DPoP token type; certificate-bound
        // (mTLS) tokens remain Bearer (RFC 8705 §3.1).
        tokenType: isNonEmptyString(grant.dpopJkt) ? 'DPoP' : 'Bearer',
        expiresIn: expiresInSec,
        jti: token.jti,
      };
    },

    /**
     * Verify a JWT access token for introspection (RFC 7662). A bad
     * signature / expired token is simply `{ active: false }` — never a
     * thrown error, since introspection reports inactivity, not failure.
     *
     * @param {string} token
     * @param {{ issuer: string }} ctx
     * @returns {Promise<{ active: boolean, claims?: Record<string, unknown> }>}
     */
    async introspect(token, ctx) {
      if (!isNonEmptyString(token)) {
        return { active: false };
      }
      try {
        const { payload } = await verify(token, verificationKey, {
          alg: [alg],
          issuer: ctx.issuer,
        });
        return { active: true, claims: payload };
      } catch (err) {
        if (err instanceof JwtError) {
          return { active: false };
        }
        throw err;
      }
    },
  };
}

/**
 * Build the `cnf` confirmation claim from a DPoP thumbprint or an
 * explicit confirmation object (e.g. mTLS `x5t#S256`).
 *
 * @param {AccessGrant & { confirmation?: Record<string, unknown> }} grant
 * @returns {Record<string, unknown> | undefined}
 */
function resolveConfirmation(grant) {
  if (isNonEmptyString(grant.dpopJkt)) {
    return { jkt: grant.dpopJkt };
  }
  if (isObject(grant.confirmation)) {
    return grant.confirmation;
  }
  return undefined;
}

/**
 * @param {AccessGrant} grant
 * @returns {string | string[]}
 */
function resolveAudience(grant) {
  if (Array.isArray(grant.audience) && grant.audience.length > 0) {
    return grant.audience;
  }
  if (isNonEmptyString(grant.audience)) {
    return grant.audience;
  }
  // No resource indicator: the token is scoped to the requesting client.
  // RFC 9068 still requires an `aud`, so use the client id.
  return grant.clientId;
}
