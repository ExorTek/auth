/**
 * Shared token-response assembly for the grant handlers. Mints the access
 * token through the configured issuer strategy and, when the grant is
 * allowed a refresh token, a fresh opaque refresh token bound to a token
 * family (RFC 9700 §4.14 rotation + reuse detection). The authorization-
 * code grant starts a new family; the refresh grant rotates within the
 * existing one.
 */
import { isArray, isNonEmptyString } from '@exortek/shared/predicates';

import { randomState } from '../../internal/state.js';

/**
 * @typedef {Object} GrantSubject
 * @property {string} subject
 * @property {string} clientId
 * @property {string[]} scope
 * @property {string | string[]} [audience]      resource indicator(s) → token `aud`
 * @property {string} [resource]                 the single resource bound for a refresh family
 * @property {string} [dpopJkt]                  DPoP thumbprint to sender-constrain the token
 * @property {Record<string, unknown>} [extra]   extra access-token claims (e.g. authorization_details)
 */

/**
 * Mint the access token and build the RFC 6749 §5.1 token response body.
 *
 * @param {Record<string, any>} config
 * @param {GrantSubject} grant
 * @returns {Promise<Record<string, unknown>>}
 */
export async function buildAccessResponse(config, grant) {
  const issued = await config.tokens.issue(
    {
      subject: grant.subject,
      clientId: grant.clientId,
      scope: grant.scope,
      audience: grant.audience,
      dpopJkt: grant.dpopJkt,
      confirmation: grant.confirmation,
      extra: grant.extra,
    },
    { issuer: config.issuer },
  );

  /** @type {Record<string, unknown>} */
  const body = {
    access_token: issued.accessToken,
    token_type: issued.tokenType,
    expires_in: issued.expiresIn,
  };
  if (isArray(grant.scope) && grant.scope.length > 0) {
    body.scope = grant.scope.join(' ');
  }
  return body;
}

/**
 * Whether this client+server pair issues refresh tokens for the grant.
 *
 * @param {Record<string, any>} config
 * @param {import('../clients.js').Client} client
 * @returns {boolean}
 */
export function refreshAllowed(config, client) {
  return config.grantTypes.includes('refresh_token') && client.grantTypes.includes('refresh_token');
}

/**
 * Mint and attach an OIDC `id_token` to the response body when the server
 * is an OpenID Provider (`oidc` configured) AND the grant carried the
 * `openid` scope. A no-op otherwise, so a plain OAuth 2.1 AS is unaffected.
 *
 * @param {Record<string, any>} config
 * @param {Record<string, unknown>} body            the token response being assembled (mutated on issue)
 * @param {{ subject: string, clientId: string, scope: string[], nonce?: string, authTime?: number }} grant
 * @returns {Promise<void>}
 */
export async function maybeIssueIdToken(config, body, grant) {
  if (!config.idTokenSigner || !isArray(grant.scope) || !grant.scope.includes('openid')) {
    return;
  }
  body.id_token = await config.idTokenSigner.sign({
    subject: grant.subject,
    clientId: grant.clientId,
    issuer: config.issuer,
    nonce: grant.nonce,
    authTime: grant.authTime,
    accessToken: isNonEmptyString(body.access_token) ? body.access_token : undefined,
  });
}

/**
 * Create and persist a new refresh token. `familyId` is supplied to keep
 * a rotation within its family, or omitted to start a new one.
 *
 * @param {Record<string, any>} config
 * @param {GrantSubject & { familyId?: string }} grant
 * @returns {Promise<string>} the opaque refresh token
 */
export async function mintRefreshToken(config, grant) {
  const token = randomState();
  const familyId = isNonEmptyString(grant.familyId) ? grant.familyId : randomState();
  await config.stores.refresh.save({
    token,
    familyId,
    clientId: grant.clientId,
    scope: grant.scope,
    subject: grant.subject,
    resource: grant.resource,
    dpopJkt: grant.dpopJkt,
    expiresAt: Date.now() + config.refreshTokenTtlMs,
  });
  return token;
}
