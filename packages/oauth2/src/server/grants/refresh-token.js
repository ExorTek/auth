/**
 * `refresh_token` grant (RFC 6749 §6) with rotation + reuse detection
 * (RFC 9700 §4.14). Every use rotates the token within its family; a
 * presentation of an already-rotated token is treated as theft and
 * revokes the whole family. Scope may be narrowed but never widened, and
 * a DPoP-bound token stays bound to the same key.
 */
import { isNonEmptyString, isNumber } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';
import { randomState } from '../../internal/state.js';
import { resolveTokenAudience } from '../security/resource.js';
import { buildAccessResponse } from './_issue.js';

/**
 * @param {import('../request.js').ServerRequest} req
 * @param {{ config: Record<string, any>, client: import('../clients.js').Client, dpopJkt?: string }} ctx
 * @returns {Promise<Record<string, unknown>>}
 */
export async function refreshTokenGrant(req, ctx) {
  const { config, client } = ctx;

  if (!client.grantTypes.includes('refresh_token')) {
    throw new ServerError(ProtocolError.UNAUTHORIZED_CLIENT, 'client may not use the refresh_token grant');
  }

  const presented = req.form.refresh_token;
  if (!isNonEmptyString(presented)) {
    throw new ServerError(ProtocolError.INVALID_REQUEST, 'missing refresh_token');
  }

  const record = await config.stores.refresh.get(presented);
  if (!record) {
    throw new ServerError(ProtocolError.INVALID_GRANT, 'refresh token is invalid or expired');
  }

  // Reuse of a rotated/revoked token — the token has leaked. Burn the
  // family so the attacker and the victim both lose access.
  if (record.used === true || record.revoked === true) {
    await config.stores.refresh.revokeFamily(record.familyId);
    throw new ServerError(
      ProtocolError.INVALID_GRANT,
      'refresh token reuse detected; the token family has been revoked',
    );
  }

  if (record.clientId !== client.clientId) {
    throw new ServerError(ProtocolError.INVALID_GRANT, 'refresh token was issued to a different client');
  }

  if (isNonEmptyString(record.dpopJkt) && record.dpopJkt !== ctx.dpopJkt) {
    throw new ServerError(ProtocolError.INVALID_GRANT, 'DPoP key does not match the one bound to the refresh token');
  }

  const scope = narrowScope(req.form.scope, record.scope);
  const audience = resolveTokenAudience(req.form.resource, record.resource, config);

  // Rotate before issuing anything: mint the successor in the same family
  // and claim the presented token. The store's rotate is a compare-and-set,
  // so of two simultaneous redemptions of the SAME token exactly one wins;
  // the loser is handled exactly like a replay and burns the family.
  //
  // The successor inherits the family's absolute expiry: rotation renews the
  // token, not the grant, so a refresh family still dies `refreshTokenTtl`
  // after the user authorized it. (A record written before expiries were
  // carried gets a fresh one rather than none.)
  const nextToken = randomState();
  const rotated = await config.stores.refresh.rotate(presented, {
    token: nextToken,
    familyId: record.familyId,
    clientId: client.clientId,
    // RFC 6749 §6: the new refresh token's scope MUST be identical to the
    // presented one's — a narrowed request narrows this access token only.
    scope: record.scope,
    subject: record.subject,
    resource: record.resource,
    dpopJkt: record.dpopJkt,
    expiresAt: isNumber(record.expiresAt) ? record.expiresAt : Date.now() + config.refreshTokenTtlMs,
  });
  if (rotated === false) {
    await config.stores.refresh.revokeFamily(record.familyId);
    throw new ServerError(
      ProtocolError.INVALID_GRANT,
      'refresh token reuse detected; the token family has been revoked',
    );
  }

  const body = await buildAccessResponse(config, {
    subject: record.subject,
    clientId: client.clientId,
    scope,
    audience,
    dpopJkt: record.dpopJkt,
  });
  body.refresh_token = nextToken;

  return body;
}

/**
 * Requested scope must be a subset of the originally granted scope
 * (RFC 6749 §6); absent request → the full granted scope.
 *
 * @param {string | undefined} requested
 * @param {string[]} granted
 * @returns {string[]}
 */
function narrowScope(requested, granted) {
  if (!isNonEmptyString(requested)) {
    return granted;
  }
  const asked = requested.split(/\s+/).filter(Boolean);
  for (const s of asked) {
    if (!granted.includes(s)) {
      throw new ServerError(
        ProtocolError.INVALID_SCOPE,
        `scope ${JSON.stringify(s)} exceeds the originally granted scope`,
      );
    }
  }
  return asked;
}
