/**
 * Token introspection endpoint (RFC 7662). An authenticated caller (a
 * protected resource, or the client itself) submits a `token` and learns
 * whether it is active and, if so, its metadata. A refresh token is
 * resolved from the store; a JWT access token is verified through the
 * issuer strategy. An unknown, expired, or reused token is simply
 * `{ active: false }` — never an error, and never leaking why.
 *
 * The endpoint requires client authentication (RFC 7662 §2.1) so it can't
 * be used as an open token oracle. By default a client may introspect only
 * its OWN tokens — a token owned by a different client reads back inactive,
 * so no client becomes an oracle over another's tokens (or, via `sub`, over
 * user identities). Deployments where trusted resource servers must
 * introspect any client's token opt in with
 * `introspection: { allowCrossClient: true }`.
 */
import { isArray, isNonEmptyString, isObject } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';
import { normalizeRequest } from '../request.js';
import { json, jsonError } from '../response.js';
import { authenticateClient } from '../security/client-auth.js';

const INACTIVE = Object.freeze({ active: false });

/**
 * @param {Record<string, any>} config
 * @returns {(raw: import('../request.js').RawRequest) => Promise<import('../response.js').ServerResponse>}
 */
export function createIntrospectHandler(config) {
  return async function introspectHandler(raw) {
    try {
      const req = normalizeRequest(raw);
      if (req.method !== 'POST') {
        throw new ServerError(ProtocolError.INVALID_REQUEST, 'the introspection endpoint only accepts POST');
      }

      const client = await authenticateClient(req, config);

      const token = req.form.token;
      if (!isNonEmptyString(token)) {
        throw new ServerError(ProtocolError.INVALID_REQUEST, 'missing token');
      }

      const response =
        (await introspectRefresh(config, token, client)) ?? (await introspectAccess(config, token, client));
      return json(200, response ?? INACTIVE);
    } catch (err) {
      if (err instanceof ServerError) {
        return jsonError(err);
      }
      throw err;
    }
  };
}

/**
 * Resolve an opaque refresh token from the store.
 *
 * @param {Record<string, any>} config
 * @param {string} token
 * @param {import('../clients.js').Client} client
 * @returns {Promise<Record<string, unknown> | undefined>}
 */
async function introspectRefresh(config, token, client) {
  const record = await config.stores.refresh.get(token);
  if (!record || record.used === true || record.revoked === true) {
    return undefined;
  }
  // Own-token only, unless cross-client introspection is opted in.
  if (!ownsToken(config, client, record.clientId)) {
    return undefined;
  }
  return {
    active: true,
    token_type: 'refresh_token',
    client_id: record.clientId,
    sub: record.subject,
    scope: isArray(record.scope) ? record.scope.join(' ') : undefined,
    aud: record.resource,
    iss: config.issuer,
  };
}

/**
 * Verify a JWT access token through the issuer strategy and project its
 * claims onto the RFC 7662 §2.2 response shape.
 *
 * @param {Record<string, any>} config
 * @param {string} token
 * @param {import('../clients.js').Client} client
 * @returns {Promise<Record<string, unknown> | undefined>}
 */
async function introspectAccess(config, token, client) {
  const { active, claims } = await config.tokens.introspect(token, { issuer: config.issuer });
  if (!active || !claims) {
    return undefined;
  }
  if (!ownsToken(config, client, claims.client_id)) {
    return undefined;
  }
  return {
    active: true,
    // A DPoP-bound access token (carries `cnf.jkt`) reads back as `DPoP`,
    // not `Bearer` — the resource server must present a proof for it.
    token_type: isObject(claims.cnf) && isNonEmptyString(claims.cnf.jkt) ? 'DPoP' : 'Bearer',
    scope: isNonEmptyString(claims.scope) ? claims.scope : undefined,
    client_id: claims.client_id,
    sub: claims.sub,
    aud: claims.aud,
    iss: claims.iss,
    exp: claims.exp,
    iat: claims.iat,
    jti: claims.jti,
    cnf: claims.cnf,
    authorization_details: claims.authorization_details,
  };
}

/**
 * Whether `client` may see a token owned by `ownerClientId` — its own
 * always, any client only when cross-client introspection is enabled.
 *
 * @param {Record<string, any>} config
 * @param {import('../clients.js').Client} client
 * @param {unknown} ownerClientId
 * @returns {boolean}
 */
function ownsToken(config, client, ownerClientId) {
  if (config.introspection?.allowCrossClient === true) {
    return true;
  }
  return ownerClientId === client.clientId;
}
