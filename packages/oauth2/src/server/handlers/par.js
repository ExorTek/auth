/**
 * Pushed Authorization Requests — PAR (RFC 9126). The client POSTs the
 * authorization parameters through the authenticated back channel and
 * receives a `request_uri` to use at the authorization endpoint, so the
 * parameters never ride the front channel or browser history. When the
 * server (or a client's registration) requires PAR, the plain
 * front-channel authorize request is refused.
 *
 * The pushed parameters are stored verbatim and consumed once at
 * `/authorize`; all the security validation (PKCE, redirect_uri, scope,
 * resource, RAR) runs there, against the identical params, so PAR adds a
 * confidential channel without duplicating the checks.
 */
import { isNonEmptyString } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';
import { randomState } from '../../internal/state.js';
import { normalizeRequest } from '../request.js';
import { json, jsonError } from '../response.js';
import { authenticateClient } from '../security/client-auth.js';
import { resolveDpopBinding } from '../security/dpop.js';

const REQUEST_URI_PREFIX = 'urn:ietf:params:oauth:request_uri:';

// Params consumed by client authentication — never stored as authorize
// request parameters.
const CLIENT_AUTH_PARAMS = new Set(['client_secret', 'client_assertion', 'client_assertion_type']);

/**
 * @param {Record<string, any>} config
 * @returns {(raw: import('../request.js').RawRequest) => Promise<import('../response.js').ServerResponse>}
 */
export function createParHandler(config) {
  return async function parHandler(raw) {
    try {
      const req = normalizeRequest(raw);
      if (req.method !== 'POST') {
        throw new ServerError(ProtocolError.INVALID_REQUEST, 'the PAR endpoint only accepts POST');
      }

      const client = await authenticateClient(req, config);

      // RFC 9126 §2.1: a PAR request must not itself carry a request_uri.
      if (isNonEmptyString(req.form.request_uri)) {
        throw new ServerError(
          ProtocolError.INVALID_REQUEST,
          'a pushed authorization request must not contain request_uri',
        );
      }
      // The pushed client_id must match the authenticated client.
      if (isNonEmptyString(req.form.client_id) && req.form.client_id !== client.clientId) {
        throw new ServerError(ProtocolError.INVALID_REQUEST, 'client_id does not match the authenticated client');
      }

      // A DPoP proof at PAR pre-binds the eventual code to the client key
      // (RFC 9449 §10.1) via `dpop_jkt`.
      const { dpopJkt } = await resolveDpopBinding(req, config, client);

      const params = collectParams(req.form, client.clientId, dpopJkt);
      const requestUri = REQUEST_URI_PREFIX + randomState();
      config.stores.par.save(requestUri, params, config.parTtlMs);

      return json(201, {
        request_uri: requestUri,
        expires_in: Math.floor(config.parTtlMs / 1000),
      });
    } catch (err) {
      if (err instanceof ServerError) {
        return jsonError(err);
      }
      throw err;
    }
  };
}

/**
 * @param {Record<string, string>} form
 * @param {string} clientId
 * @param {string | undefined} dpopJkt
 * @returns {Record<string, unknown>}
 */
function collectParams(form, clientId, dpopJkt) {
  /** @type {Record<string, unknown>} */
  const params = {};
  for (const [key, value] of Object.entries(form)) {
    if (!CLIENT_AUTH_PARAMS.has(key)) {
      params[key] = value;
    }
  }
  params.client_id = clientId;
  if (isNonEmptyString(dpopJkt)) {
    params.dpop_jkt = dpopJkt;
  }
  return params;
}
