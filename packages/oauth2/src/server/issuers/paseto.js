/**
 * PASETO access-token issuer — the alternative to {@link jwtIssuer}
 * (PLAN: "token issuance via @exortek/jwt or @exortek/paseto — caller's
 * choice"). Same strategy contract (`issue` / `introspect`) so
 * `createServer` neither knows nor cares which backend mints the token.
 *
 * Uses PASETO v4.public (Ed25519) — a signed, publicly-verifiable token a
 * resource server checks with the public key, mirroring the JWT profile.
 * PASETO has no `typ`/`cnf` header the way a JWS does; RFC-9068-style
 * claims (`client_id`, `scope`, `cnf`) live in the payload, DPoP binding
 * included.
 */
import { sign, verify, PasetoError } from '@exortek/paseto';
import { parseDuration } from '@exortek/shared/duration';
import { isArray, isNonEmptyString, isNullish, isObject } from '@exortek/shared/predicates';

import { ErrorCode, OAuth2Error } from '../../internal/errors.js';
import { randomState } from '../../internal/state.js';

const DEFAULT_EXPIRES_IN = '10m';

/**
 * @typedef {Object} PasetoIssuerConfig
 * @property {import('node:crypto').KeyObject | Uint8Array} secretKey   Ed25519 secret (signing)
 * @property {import('node:crypto').KeyObject | Uint8Array} publicKey   Ed25519 public (introspection)
 * @property {string | number} [expiresIn]                             access-token lifetime (default `'10m'`)
 */

/**
 * @param {PasetoIssuerConfig} config
 */
export function pasetoIssuer(config) {
  if (!isObject(config)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'pasetoIssuer requires a config object');
  }
  if (isNullish(config.secretKey) || isNullish(config.publicKey)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'pasetoIssuer requires secretKey and publicKey');
  }
  const { secretKey, publicKey } = config;
  const expiresInSec = Math.floor(parseDuration(config.expiresIn ?? DEFAULT_EXPIRES_IN) / 1000);

  return {
    /**
     * @param {import('./jwt.js').AccessGrant} grant
     * @param {import('./jwt.js').GrantContext} ctx
     * @returns {Promise<{ accessToken: string, tokenType: string, expiresIn: number, jti: string }>}
     */
    async issue(grant, ctx) {
      const jti = randomState();
      /** @type {Record<string, unknown>} */
      const claims = {
        client_id: grant.clientId,
        ...(isObject(grant.extra) ? grant.extra : {}),
      };
      if (isArray(grant.scope) && grant.scope.length > 0) {
        claims.scope = grant.scope.join(' ');
      }
      if (isNonEmptyString(grant.dpopJkt)) {
        claims.cnf = { jkt: grant.dpopJkt };
      } else if (isObject(grant.confirmation)) {
        claims.cnf = grant.confirmation;
      }

      const token = sign(claims, secretKey, {
        issuer: ctx.issuer,
        subject: grant.subject,
        audience: audienceString(grant),
        jti,
        expiresIn: expiresInSec,
      });

      return {
        accessToken: token,
        tokenType: isNonEmptyString(grant.dpopJkt) ? 'DPoP' : 'Bearer',
        expiresIn: expiresInSec,
        jti,
      };
    },

    /**
     * @param {string} token
     * @param {{ issuer: string }} ctx
     * @returns {Promise<{ active: boolean, claims?: Record<string, unknown> }>}
     */
    async introspect(token, ctx) {
      if (!isNonEmptyString(token)) {
        return { active: false };
      }
      try {
        const payload = verify(token, publicKey, { issuer: ctx.issuer });
        return { active: true, claims: /** @type {Record<string, unknown>} */ (payload) };
      } catch (err) {
        if (err instanceof PasetoError) {
          return { active: false };
        }
        throw err;
      }
    },
  };
}

/**
 * PASETO `aud` is a single registered claim string; join a multi-resource
 * grant with a space (mirrors how `scope` is encoded).
 *
 * @param {import('./jwt.js').AccessGrant} grant
 * @returns {string}
 */
function audienceString(grant) {
  if (isArray(grant.audience) && grant.audience.length > 0) {
    return grant.audience.join(' ');
  }
  if (isNonEmptyString(grant.audience)) {
    return grant.audience;
  }
  return grant.clientId;
}
