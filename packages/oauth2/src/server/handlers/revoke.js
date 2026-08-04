/**
 * Token revocation endpoint (RFC 7009). An authenticated client submits a
 * `token` and the server invalidates it. Revoking a refresh token burns
 * its whole rotation family (RFC 7009 §2.1 — related tokens SHOULD be
 * revoked); access tokens are short-lived JWTs and simply age out.
 *
 * Per RFC 7009 §2.2 the endpoint returns `200` for a token that is
 * unknown, already revoked, or not owned by the caller — revocation is
 * idempotent and must not leak whether a token existed. Only a bad
 * request or failed client authentication is an error.
 */
import { isNonEmptyString } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';
import { normalizeRequest } from '../request.js';
import { json, jsonError } from '../response.js';
import { authenticateClient } from '../security/client-auth.js';

/**
 * @param {Record<string, any>} config
 * @returns {(raw: import('../request.js').RawRequest) => Promise<import('../response.js').ServerResponse>}
 */
export function createRevokeHandler(config) {
  return async function revokeHandler(raw) {
    try {
      const req = normalizeRequest(raw);
      if (req.method !== 'POST') {
        throw new ServerError(ProtocolError.INVALID_REQUEST, 'the revocation endpoint only accepts POST');
      }

      const client = await authenticateClient(req, config);

      const token = req.form.token;
      if (!isNonEmptyString(token)) {
        throw new ServerError(ProtocolError.INVALID_REQUEST, 'missing token');
      }

      // Only refresh tokens are stateful here. Revoke the family, but only
      // when the token belongs to the caller — a client must not revoke
      // another client's token. Ownership mismatch is silently a no-op
      // (still 200), matching the "don't leak existence" rule.
      const record = await config.stores.refresh.get(token);
      if (record && record.clientId === client.clientId) {
        await config.stores.refresh.revokeFamily(record.familyId);
      }

      return json(200, {});
    } catch (err) {
      if (err instanceof ServerError) {
        return jsonError(err);
      }
      throw err;
    }
  };
}
