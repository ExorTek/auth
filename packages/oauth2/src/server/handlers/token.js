/**
 * Token endpoint (RFC 6749 §3.2). Authenticates the client, then
 * dispatches by `grant_type` to the matching grant handler. The core
 * grants — `authorization_code`, `refresh_token`, `client_credentials` —
 * are wired here; the device-code and token-exchange grants extend the
 * dispatch table in the Tier C step. Every response is `no-store` JSON
 * (RFC 6749 §5.1); every protocol failure renders as the §5.2 error body.
 */
import { isNonEmptyString } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';
import { normalizeRequest } from '../request.js';
import { json, jsonError } from '../response.js';
import { authenticateClient, certificateConfirmation } from '../security/client-auth.js';
import { resolveDpopBinding } from '../security/dpop.js';
import { authorizationCodeGrant } from '../grants/authorization-code.js';
import { refreshTokenGrant } from '../grants/refresh-token.js';
import { clientCredentialsGrant } from '../grants/client-credentials.js';
import { deviceCodeGrant } from '../grants/device-code.js';
import { tokenExchangeGrant } from '../grants/token-exchange.js';

/**
 * @param {Record<string, any>} config
 * @returns {(raw: import('../request.js').RawRequest) => Promise<import('../response.js').ServerResponse>}
 */
export function createTokenHandler(config) {
  const grants = buildGrantTable(config);

  return async function tokenHandler(raw) {
    try {
      const req = normalizeRequest(raw);
      if (req.method !== 'POST') {
        throw new ServerError(ProtocolError.INVALID_REQUEST, 'the token endpoint only accepts POST');
      }

      const grantType = req.form.grant_type;
      if (!isNonEmptyString(grantType)) {
        throw new ServerError(ProtocolError.INVALID_REQUEST, 'missing grant_type');
      }
      const grant = grants[grantType];
      if (!grant || !config.grantTypes.includes(grantType)) {
        throw new ServerError(
          ProtocolError.UNSUPPORTED_GRANT_TYPE,
          `unsupported grant_type ${JSON.stringify(grantType)}`,
        );
      }

      const client = await authenticateClient(req, config);
      // Resolve any DPoP proof once so the grant can bind / verify the key
      // (RFC 9449). Returns undefined when the request carries no proof.
      const { dpopJkt, nonceHeaders } = await resolveDpopBinding(req, config, client);
      // A certificate-authenticated client gets certificate-bound tokens
      // (RFC 8705 §3) unless DPoP already sender-constrains them.
      const confirmation = dpopJkt ? undefined : certificateConfirmation(req, client);

      const body = await grant(req, { config, client, dpopJkt, confirmation });
      return json(200, body, nonceHeaders);
    } catch (err) {
      if (err instanceof ServerError) {
        return jsonError(err);
      }
      throw err;
    }
  };
}

/**
 * @param {Record<string, any>} _config
 * @returns {Record<string, (req: any, ctx: any) => Promise<Record<string, unknown>>>}
 */
function buildGrantTable(_config) {
  return {
    authorization_code: authorizationCodeGrant,
    refresh_token: refreshTokenGrant,
    client_credentials: clientCredentialsGrant,
    'urn:ietf:params:oauth:grant-type:device_code': deviceCodeGrant,
    'urn:ietf:params:oauth:grant-type:token-exchange': tokenExchangeGrant,
  };
}
