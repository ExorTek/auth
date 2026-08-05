/**
 * Authorization Server Metadata (RFC 8414) — the document a client (or
 * `@exortek/oauth2`'s own RP-side `discover()`) fetches from
 * `/.well-known/oauth-authorization-server` to auto-configure. This is
 * the producing half; `internal/discovery.js` is the consuming half, and
 * both speak the same snake_case wire vocabulary.
 *
 * The document is built once from the server config and is cacheable
 * (unlike token responses, which are `no-store`).
 */
import { isArray, isNonEmptyString } from '@exortek/shared/predicates';

/**
 * Assemble the metadata document from the resolved server config. Only
 * capabilities the server actually offers are advertised — an absent
 * endpoint (e.g. no device grant) is omitted, not sent empty.
 *
 * @param {import('../index.js').ResolvedServerConfig} config
 * @returns {Record<string, unknown>}
 */
export function buildMetadata(config) {
  const { issuer, endpoints, grantTypes, scopes, authMethods, dpopAlgs, requirePar } = config;

  /** @type {Record<string, unknown>} */
  const doc = {
    issuer,
    authorization_endpoint: endpoints.authorization,
    token_endpoint: endpoints.token,
    // RFC 8414 requires response_types_supported; this AS is code-only
    // (OAuth 2.1 drops the implicit and hybrid response types).
    response_types_supported: ['code'],
    // `jwt` (JARM, RFC 9101) is advertised only when the server can sign it.
    response_modes_supported: config.jarm ? ['query', 'jwt'] : ['query'],
    grant_types_supported: grantTypes,
    token_endpoint_auth_methods_supported: authMethods,
    // PKCE S256 only — `plain` is never offered (OAuth 2.1 / Decision #0).
    code_challenge_methods_supported: ['S256'],
    // RFC 9207 — this server always returns `iss` on the authorization
    // response, the strongest mix-up defense.
    authorization_response_iss_parameter_supported: true,
  };

  if (isNonEmptyString(config.jwksUri)) {
    doc.jwks_uri = config.jwksUri;
  }
  if (isArray(scopes) && scopes.length > 0) {
    doc.scopes_supported = scopes;
  }
  if (isNonEmptyString(endpoints.introspection)) {
    doc.introspection_endpoint = endpoints.introspection;
  }
  if (isNonEmptyString(endpoints.revocation)) {
    doc.revocation_endpoint = endpoints.revocation;
  }
  if (isNonEmptyString(endpoints.par)) {
    doc.pushed_authorization_request_endpoint = endpoints.par;
    // RFC 9126 §5 — advertise when PAR is mandatory server-wide.
    doc.require_pushed_authorization_requests = requirePar === true;
  }
  if (isNonEmptyString(endpoints.deviceAuthorization)) {
    doc.device_authorization_endpoint = endpoints.deviceAuthorization;
  }
  if (isArray(dpopAlgs) && dpopAlgs.length > 0) {
    // RFC 9449 §5.1 — advertise the DPoP proof signing algs we accept.
    doc.dpop_signing_alg_values_supported = dpopAlgs;
  }

  return doc;
}

/**
 * Build the cacheable metadata handler. The document is computed once at
 * server-construction time.
 *
 * @param {import('../index.js').ResolvedServerConfig} config
 * @returns {() => import('../response.js').ServerResponse}
 */
export function createMetadataHandler(config) {
  const body = JSON.stringify(buildMetadata(config));
  return function metadataHandler() {
    return {
      status: 200,
      headers: {
        'content-type': 'application/json',
        // Metadata is stable; let clients and caches keep it.
        'cache-control': 'public, max-age=3600',
      },
      body,
    };
  };
}
