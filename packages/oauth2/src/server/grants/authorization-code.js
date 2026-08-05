/**
 * `authorization_code` grant (RFC 6749 §4.1.3). Redeems a single-use code
 * for tokens after re-checking every binding made at the authorize step:
 * the code belongs to this client, the `redirect_uri` is identical, and
 * the PKCE `code_verifier` matches the bound challenge. A DPoP-bound code
 * additionally requires the same key at the token endpoint (RFC 9449).
 */
import { isNonEmptyString } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';
import { verifyCodeVerifier } from '../security/pkce.js';
import { resolveTokenAudience } from '../security/resource.js';
import { buildAccessResponse, refreshAllowed, mintRefreshToken, maybeIssueIdToken } from './_issue.js';

/**
 * @param {import('../request.js').ServerRequest} req
 * @param {{ config: Record<string, any>, client: import('../clients.js').Client, dpopJkt?: string }} ctx
 * @returns {Promise<Record<string, unknown>>}
 */
export async function authorizationCodeGrant(req, ctx) {
  const { config, client } = ctx;

  if (!client.grantTypes.includes('authorization_code')) {
    throw new ServerError(ProtocolError.UNAUTHORIZED_CLIENT, 'client may not use the authorization_code grant');
  }

  const code = req.form.code;
  if (!isNonEmptyString(code)) {
    throw new ServerError(ProtocolError.INVALID_REQUEST, 'missing code');
  }

  // Single-use: consuming the code here means a replay finds nothing.
  const record = await config.stores.authCode.consume(code);
  if (!record) {
    throw new ServerError(ProtocolError.INVALID_GRANT, 'authorization code is invalid, expired, or already used');
  }
  if (record.clientId !== client.clientId) {
    throw new ServerError(ProtocolError.INVALID_GRANT, 'authorization code was issued to a different client');
  }

  // RFC 6749 §4.1.3: redirect_uri must be present and identical when it
  // was included in the authorization request (it always is here).
  if (req.form.redirect_uri !== record.redirectUri) {
    throw new ServerError(ProtocolError.INVALID_GRANT, 'redirect_uri does not match the authorization request');
  }

  verifyCodeVerifier(req.form.code_verifier, record.codeChallenge);

  // RFC 9449 §10: the token is bound to the key proven on THIS token
  // request (`ctx.dpopJkt`). If the code was pre-bound at authorize time
  // (the optional `dpop_jkt` param → `record.dpopJkt`), that binding must
  // match the presented key.
  if (isNonEmptyString(record.dpopJkt) && record.dpopJkt !== ctx.dpopJkt) {
    throw new ServerError(
      ProtocolError.INVALID_GRANT,
      'DPoP key does not match the one bound to the authorization code',
    );
  }
  const dpopJkt = ctx.dpopJkt ?? record.dpopJkt;

  const audience = resolveTokenAudience(req.form.resource, record.resource, config);

  const body = await buildAccessResponse(config, {
    subject: record.subject,
    clientId: client.clientId,
    scope: record.scope,
    audience,
    dpopJkt,
    confirmation: ctx.confirmation,
    extra: buildExtraClaims(record),
  });

  // OIDC: an `openid`-scoped request on an OpenID Provider gets an id_token
  // bound to the access token (`at_hash`), the request `nonce`, and the
  // authentication time captured at the authorize step.
  await maybeIssueIdToken(config, body, {
    subject: record.subject,
    clientId: client.clientId,
    scope: record.scope,
    nonce: record.nonce,
    authTime: record.authTime,
  });

  if (refreshAllowed(config, client)) {
    body.refresh_token = await mintRefreshToken(config, {
      subject: record.subject,
      clientId: client.clientId,
      scope: record.scope,
      resource: record.resource,
      dpopJkt,
    });
  }

  return body;
}

/**
 * @param {Record<string, any>} record
 * @returns {Record<string, unknown> | undefined}
 */
function buildExtraClaims(record) {
  if (record.authorizationDetails === undefined) {
    return undefined;
  }
  // RFC 9396 §7: granted authorization_details are reflected into the
  // access token so the resource server can enforce them.
  return { authorization_details: record.authorizationDetails };
}
