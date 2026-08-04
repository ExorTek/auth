/**
 * Token introspection endpoint (RFC 7662). An authenticated caller (a
 * protected resource, or the client itself) submits a `token` and learns
 * whether it is active and, if so, its metadata. A refresh token is
 * resolved from the store; a JWT access token is verified through the
 * issuer strategy. An unknown, expired, or reused token is simply
 * `{ active: false }` — never an error, and never leaking why.
 *
 * The endpoint requires client authentication (RFC 7662 §2.1) so it can't
 * be used as an open token oracle.
 */
import { isNonEmptyString } from '@exortek/shared/predicates';

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

      await authenticateClient(req, config);

      const token = req.form.token;
      if (!isNonEmptyString(token)) {
        throw new ServerError(ProtocolError.INVALID_REQUEST, 'missing token');
      }

      const response = (await introspectRefresh(config, token)) ?? (await introspectAccess(config, token));
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
 * @returns {Promise<Record<string, unknown> | undefined>}
 */
async function introspectRefresh(config, token) {
  const record = await config.stores.refresh.get(token);
  if (!record || record.used === true || record.revoked === true) {
    return undefined;
  }
  return {
    active: true,
    token_type: 'refresh_token',
    client_id: record.clientId,
    sub: record.subject,
    scope: Array.isArray(record.scope) ? record.scope.join(' ') : undefined,
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
 * @returns {Promise<Record<string, unknown> | undefined>}
 */
async function introspectAccess(config, token) {
  const { active, claims } = await config.tokens.introspect(token, { issuer: config.issuer });
  if (!active || !claims) {
    return undefined;
  }
  return {
    active: true,
    token_type: 'Bearer',
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
