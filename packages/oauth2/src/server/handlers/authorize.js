/**
 * Authorization endpoint (RFC 6749 §4.1.1, OAuth 2.1). Code grant only —
 * the implicit and hybrid response types are gone. PKCE S256 is required
 * (Decision #0); `state` is echoed and `iss` is always returned (RFC
 * 9207). Errors only redirect back to the client once the `client_id` and
 * an exact-matching `redirect_uri` are trusted — an unknown client or a
 * bad redirect URI is shown directly, never bounced (open-redirect lever).
 *
 * The resource owner's identity comes from the caller's `authenticateUser`
 * hook: the host application owns login + consent UI and routes to this
 * handler only once the user has authenticated and approved the request.
 * A `null` result is treated as the user declining (`access_denied`).
 */
import { isNonEmptyString } from '@exortek/shared/predicates';

import { randomState } from '../../internal/state.js';
import { ProtocolError, ServerError } from '../errors.js';
import { normalizeRequest } from '../request.js';
import { redirect, redirectError, jsonError } from '../response.js';
import { resolvePkceChallenge } from '../security/pkce.js';
import { validateResource } from '../security/resource.js';
import { validateAuthorizationDetails } from '../security/rar.js';
import { verifyRequestObject, signJarmResponse } from '../security/jar-jarm.js';

/**
 * @param {import('../index.js').ResolvedServerConfig & Record<string, any>} config
 * @returns {(raw: import('../request.js').RawRequest) => Promise<import('../response.js').ServerResponse>}
 */
export function createAuthorizeHandler(config) {
  return async function authorizeHandler(raw) {
    const req = normalizeRequest(raw);
    // Untrusted until the client + redirect URI are validated.
    let redirectUri;
    try {
      const params = await resolveRequestParams(req, config);
      const client = await requireClient(params.client_id, config);

      redirectUri = requireRegisteredRedirectUri(params.redirect_uri, client);
      // From here every failure is redirectable back to the client.
      const state = isNonEmptyString(params.state) ? params.state : undefined;

      if (params.response_type !== 'code') {
        throw redirectable(ProtocolError.UNSUPPORTED_RESPONSE_TYPE, 'only response_type=code is supported', state);
      }
      if (config.requirePar && !params._fromPar) {
        throw redirectable(ProtocolError.INVALID_REQUEST, 'this server requires a pushed authorization request', state);
      }

      const challenge = resolvePkceChallenge(params, { required: config.requirePkce, redirectableState: state });
      const scope = resolveScope(params.scope, config, state);

      // RFC 8707 resource indicator + RFC 9396 authorization_details are
      // validated up front so a malformed request fails before a code is
      // ever issued.
      const resource = isNonEmptyString(params.resource)
        ? validateResourceRedirectable(params.resource, state)
        : undefined;
      const authorizationDetails = validateAuthorizationDetails(params.authorization_details, {
        allowedTypes: config.authorizationDetailsTypes,
        redirectableState: state,
      });

      const authn = await config.authenticateUser(req);
      if (!authn || !isNonEmptyString(authn.subject)) {
        throw redirectable(ProtocolError.ACCESS_DENIED, 'the resource owner did not authorize the request', state);
      }

      const code = randomState();
      await config.stores.authCode.save(
        code,
        {
          clientId: client.clientId,
          redirectUri,
          codeChallenge: challenge.codeChallenge,
          scope,
          nonce: isNonEmptyString(params.nonce) ? params.nonce : undefined,
          subject: authn.subject,
          authTime: authn.authTime,
          resource,
          authorizationDetails,
          dpopJkt: isNonEmptyString(params.dpop_jkt) ? params.dpop_jkt : undefined,
        },
        config.authorizationCodeTtlMs,
      );

      // JARM (response_mode=jwt): return the response params as a signed
      // JWT instead of bare query params (RFC 9101 / OIDC JARM).
      if (params.response_mode === 'jwt') {
        const response = await signJarmResponse({ code, state, iss: config.issuer }, client.clientId, config);
        return redirect(redirectUri, { response });
      }
      return redirect(redirectUri, { code, state, iss: config.issuer });
    } catch (err) {
      if (err instanceof ServerError && err.redirectable) {
        return redirectError(redirectUri, err, { issuer: config.issuer });
      }
      if (err instanceof ServerError) {
        return jsonError(err);
      }
      throw err;
    }
  };
}

// PARAMS

/**
 * The authorization request parameters. When PAR is used the params were
 * pushed via the back channel and are looked up by `request_uri`
 * (RFC 9126); the JAR signed-request-object path (RFC 9101) is layered in
 * `security/jar-jarm.js`. Plain front-channel query params are the base.
 *
 * @param {import('../request.js').ServerRequest} req
 * @param {Record<string, any>} config
 * @returns {Promise<Record<string, any>>}
 */
async function resolveRequestParams(req, config) {
  const requestUri = req.query.request_uri;
  if (isNonEmptyString(requestUri)) {
    const pushed = config.stores.par.consume(requestUri);
    if (!pushed) {
      throw new ServerError(ProtocolError.INVALID_REQUEST, 'request_uri is unknown, expired, or already used');
    }
    return { ...pushed, _fromPar: true };
  }
  // JAR (RFC 9101): a signed request object supersedes the query params.
  if (isNonEmptyString(req.query.request)) {
    return verifyRequestObject(req.query.request, req.query.client_id, config);
  }
  return { ...req.query };
}

/**
 * @param {string | undefined} clientId
 * @param {Record<string, any>} config
 */
async function requireClient(clientId, config) {
  if (!isNonEmptyString(clientId)) {
    throw new ServerError(ProtocolError.INVALID_REQUEST, 'missing client_id');
  }
  const client = await config.registry.getClient(clientId);
  if (!client) {
    throw new ServerError(ProtocolError.INVALID_CLIENT, `unknown client ${JSON.stringify(clientId)}`);
  }
  return client;
}

/**
 * Exact-match the presented `redirect_uri` against the client's
 * registered allowlist (RFC 6749 §3.1.2.3 / OAuth 2.1 — no prefix, no
 * wildcard). A mismatch must NOT redirect.
 *
 * @param {string | undefined} redirectUri
 * @param {import('../clients.js').Client} client
 * @returns {string}
 */
function requireRegisteredRedirectUri(redirectUri, client) {
  if (!isNonEmptyString(redirectUri)) {
    throw new ServerError(ProtocolError.INVALID_REQUEST, 'missing redirect_uri');
  }
  if (!client.redirectUris.includes(redirectUri)) {
    throw new ServerError(ProtocolError.INVALID_REQUEST, 'redirect_uri does not match a registered value');
  }
  return redirectUri;
}

/**
 * Requested scope must be a subset of the server's advertised scopes when
 * a `scopes` allowlist is configured; an unknown scope is `invalid_scope`
 * (RFC 6749 §4.1.2.1). No `scopes` config = the server does not gate on
 * scope here.
 *
 * @param {string | undefined} raw
 * @param {Record<string, any>} config
 * @param {string | undefined} state
 * @returns {string[]}
 */
function resolveScope(raw, config, state) {
  const requested = isNonEmptyString(raw) ? raw.split(/\s+/).filter(Boolean) : [];
  if (Array.isArray(config.scopes)) {
    for (const s of requested) {
      if (!config.scopes.includes(s)) {
        throw redirectable(ProtocolError.INVALID_SCOPE, `unknown scope ${JSON.stringify(s)}`, state);
      }
    }
  }
  return requested;
}

/**
 * Validate a `resource` at the authorize step, re-raising the resource
 * layer's `invalid_target` as a redirectable error (we have a trusted
 * redirect_uri here).
 *
 * @param {string} value
 * @param {string | undefined} state
 * @returns {string}
 */
function validateResourceRedirectable(value, state) {
  try {
    return validateResource(value);
  } catch (err) {
    if (err instanceof ServerError) {
      throw new ServerError(err.code, err.message, { redirectable: true, state });
    }
    throw err;
  }
}

/**
 * @param {string} code
 * @param {string} message
 * @param {string | undefined} state
 * @returns {ServerError}
 */
function redirectable(code, message, state) {
  return new ServerError(code, message, { redirectable: true, state });
}
