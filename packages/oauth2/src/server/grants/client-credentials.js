/**
 * `client_credentials` grant (RFC 6749 §4.4). The client acts for itself,
 * with no resource owner — so it must be a confidential client (a public
 * client has nothing to authenticate with) and no refresh token is issued
 * (§4.4.3). The access-token `sub` is the client itself.
 */
import { isArray, isNonEmptyString } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';
import { resolveTokenAudience } from '../security/resource.js';
import { buildAccessResponse } from './_issue.js';

/**
 * @param {import('../request.js').ServerRequest} req
 * @param {{ config: Record<string, any>, client: import('../clients.js').Client, dpopJkt?: string }} ctx
 * @returns {Promise<Record<string, unknown>>}
 */
export async function clientCredentialsGrant(req, ctx) {
  const { config, client } = ctx;

  if (!client.grantTypes.includes('client_credentials')) {
    throw new ServerError(ProtocolError.UNAUTHORIZED_CLIENT, 'client may not use the client_credentials grant');
  }
  if (client.isPublic) {
    throw new ServerError(ProtocolError.UNAUTHORIZED_CLIENT, 'client_credentials requires a confidential client');
  }

  const scope = resolveScope(req.form.scope, client, config);
  const audience = resolveTokenAudience(req.form.resource, undefined, config);

  // No resource owner: the subject is the client itself.
  return buildAccessResponse(config, {
    subject: client.clientId,
    clientId: client.clientId,
    scope,
    audience,
    dpopJkt: ctx.dpopJkt,
    confirmation: ctx.confirmation,
  });
}

/**
 * A requested scope is validated against the client's registered `scope` (or
 * the server's advertised `scopes` when the client declares none). With no
 * `scope` requested, the client's registered scope is granted — or an empty
 * scope when it registers none; never the full server scope list by default.
 *
 * @param {string | undefined} requested
 * @param {import('../clients.js').Client} client
 * @param {Record<string, any>} config
 * @returns {string[]}
 */
function resolveScope(requested, client, config) {
  if (!isNonEmptyString(requested)) {
    return isArray(client.scope) ? client.scope : [];
  }
  const asked = requested.split(/\s+/).filter(Boolean);
  const allowed = isArray(client.scope) ? client.scope : config.scopes;
  if (isArray(allowed)) {
    for (const s of asked) {
      if (!allowed.includes(s)) {
        throw new ServerError(
          ProtocolError.INVALID_SCOPE,
          `scope ${JSON.stringify(s)} is not permitted for this client`,
        );
      }
    }
  }
  return asked;
}
