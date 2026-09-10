/**
 * Build the OpenID Provider metadata served at
 * `/.well-known/openid-configuration` (OpenID Connect Discovery 1.0 §3, a
 * superset of the RFC 8414 authorization-server metadata `@exortek/oauth2`
 * already produces). Only capabilities the provider actually offers are
 * advertised — an absent endpoint is omitted, never sent empty.
 */
import { isNonEmptyString } from '@exortek/shared/predicates';

/**
 * @param {object} config                     resolved provider config
 * @param {string} config.issuer
 * @param {Record<string, string>} config.endpoints  absolute endpoint URLs (authorization/token/userinfo/jwks/endSession/checkSession/revocation/introspection/registration)
 * @param {string[]} config.scopes
 * @param {string[]} config.claimsSupported
 * @param {string[]} config.idTokenAlgs       `id_token_signing_alg_values_supported`
 * @param {string[]} [config.authMethods]     token_endpoint_auth_methods_supported
 * @returns {Record<string, unknown>}
 */
export function buildDiscoveryDocument(config) {
  const { issuer, endpoints, scopes, claimsSupported, idTokenAlgs, authMethods } = config;

  /** @type {Record<string, unknown>} */
  const doc = {
    issuer,
    authorization_endpoint: endpoints.authorization,
    token_endpoint: endpoints.token,
    jwks_uri: endpoints.jwks,
    // OAuth 2.1 is code-only — no implicit/hybrid response types.
    response_types_supported: ['code'],
    response_modes_supported: ['query', 'fragment'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: idTokenAlgs,
    scopes_supported: scopes,
    claims_supported: claimsSupported,
    // PKCE S256 only (OAuth 2.1) — `plain` is never offered.
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: authMethods ?? ['client_secret_basic', 'client_secret_post'],
    // RFC 9207 — the AS returns `iss` on the authorization response.
    authorization_response_iss_parameter_supported: true,
  };

  // Optional endpoints — advertised only when the provider serves them.
  if (isNonEmptyString(endpoints.userinfo)) {
    doc.userinfo_endpoint = endpoints.userinfo;
  }
  if (isNonEmptyString(endpoints.endSession)) {
    // OpenID Connect RP-Initiated Logout 1.0.
    doc.end_session_endpoint = endpoints.endSession;
  }
  if (isNonEmptyString(endpoints.checkSession)) {
    // OpenID Connect Session Management 1.0.
    doc.check_session_iframe = endpoints.checkSession;
  }
  if (isNonEmptyString(endpoints.revocation)) {
    doc.revocation_endpoint = endpoints.revocation;
  }
  if (isNonEmptyString(endpoints.introspection)) {
    doc.introspection_endpoint = endpoints.introspection;
  }
  if (isNonEmptyString(endpoints.registration)) {
    doc.registration_endpoint = endpoints.registration;
  }

  return doc;
}
