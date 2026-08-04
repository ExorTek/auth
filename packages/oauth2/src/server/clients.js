/**
 * Client registry — the authorization server's record of the clients it
 * will talk to. A registry answers one question, `getClient(clientId)`,
 * returning the client's descriptor (redirect-URI allowlist, allowed
 * grants, token-endpoint auth method, secret / key material). The default
 * is an in-memory registry built from a static list; a deployment can
 * pass any object exposing `getClient` (sync or async) to back it with a
 * database.
 *
 * `defineClient` validates and freezes a descriptor at configuration
 * time — a malformed client is a setup error (`OAuth2Error`
 * `INVALID_ARGUMENT`), never a per-request wire error.
 */
import { isArray, isNonEmptyString, isObject } from '@exortek/shared/predicates';

import { ErrorCode, OAuth2Error } from '../internal/errors.js';
import { requireNonEmptyString } from '../internal/guards.js';

/**
 * Token-endpoint client-authentication methods this server understands
 * (RFC 6749 §2.3, RFC 7523, RFC 8705). `none` is a public client
 * (RFC 6749 §2.1) — allowed only because PKCE is mandatory, so a public
 * client is still protected against code interception.
 */
export const AUTH_METHODS = Object.freeze([
  'none',
  'client_secret_basic',
  'client_secret_post',
  'client_secret_jwt',
  'private_key_jwt',
  'tls_client_auth',
  'self_signed_tls_client_auth',
]);

/**
 * @typedef {Object} ClientConfig
 * @property {string} clientId
 * @property {string} [clientSecret]                        confidential clients only
 * @property {string[]} redirectUris                        exact-match allowlist (RFC 6749 §3.1.2)
 * @property {string[]} [grantTypes]                        default `['authorization_code','refresh_token']`
 * @property {string[]} [responseTypes]                     default `['code']`
 * @property {string} [tokenEndpointAuthMethod]             one of {@link AUTH_METHODS}
 * @property {string[]} [scope]                             scopes the client may request (omit = server default)
 * @property {string} [jwksUri]                             for `private_key_jwt` / signed request objects
 * @property {object} [jwks]                                inline JWKS alternative to `jwksUri`
 * @property {boolean} [dpopBoundAccessTokens]              require DPoP for this client (RFC 9449 §5.2)
 * @property {boolean} [requirePushedAuthorizationRequests] require PAR (RFC 9126 §2)
 * @property {string} [tlsClientAuthSubjectDn]              expected cert subject DN for `tls_client_auth` (RFC 8705 §2.1)
 * @property {string} [certificateThumbprint]              base64url `x5t#S256` for `self_signed_tls_client_auth` (RFC 8705 §2.2)
 */

/**
 * @typedef {Readonly<ClientConfig & {
 *   grantTypes: string[], responseTypes: string[], tokenEndpointAuthMethod: string, isPublic: boolean
 * }>} Client
 */

const DEFAULT_GRANT_TYPES = ['authorization_code', 'refresh_token'];

/**
 * Validate + freeze a client descriptor.
 *
 * @param {ClientConfig} config
 * @returns {Client}
 */
export function defineClient(config) {
  if (!isObject(config)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'defineClient requires a config object');
  }
  requireNonEmptyString(config.clientId, 'client.clientId');

  if (!isArray(config.redirectUris) || config.redirectUris.length === 0) {
    throw new OAuth2Error(
      ErrorCode.INVALID_ARGUMENT,
      `client ${config.clientId} must declare at least one redirectUri`,
    );
  }
  for (const uri of config.redirectUris) {
    if (!isNonEmptyString(uri)) {
      throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, `client ${config.clientId} has an invalid redirectUri`);
    }
  }

  const authMethod =
    config.tokenEndpointAuthMethod ?? (isNonEmptyString(config.clientSecret) ? 'client_secret_basic' : 'none');
  if (!AUTH_METHODS.includes(authMethod)) {
    throw new OAuth2Error(
      ErrorCode.INVALID_ARGUMENT,
      `client ${config.clientId}: unknown tokenEndpointAuthMethod ${JSON.stringify(authMethod)}`,
    );
  }

  const isPublic = authMethod === 'none';
  // A confidential auth method with no key material is a silent
  // misconfiguration — fail loudly at setup (Decision #0).
  if (!isPublic) {
    const secretBased =
      authMethod === 'client_secret_basic' || authMethod === 'client_secret_post' || authMethod === 'client_secret_jwt';
    const keyBased = authMethod === 'private_key_jwt';
    if (secretBased && !isNonEmptyString(config.clientSecret)) {
      throw new OAuth2Error(
        ErrorCode.INVALID_ARGUMENT,
        `client ${config.clientId}: ${authMethod} needs a clientSecret`,
      );
    }
    if (keyBased && !isNonEmptyString(config.jwksUri) && !isObject(config.jwks)) {
      throw new OAuth2Error(
        ErrorCode.INVALID_ARGUMENT,
        `client ${config.clientId}: private_key_jwt needs jwksUri or jwks`,
      );
    }
    if (authMethod === 'tls_client_auth' && !isNonEmptyString(config.tlsClientAuthSubjectDn)) {
      throw new OAuth2Error(
        ErrorCode.INVALID_ARGUMENT,
        `client ${config.clientId}: tls_client_auth needs tlsClientAuthSubjectDn`,
      );
    }
    if (authMethod === 'self_signed_tls_client_auth' && !isNonEmptyString(config.certificateThumbprint)) {
      throw new OAuth2Error(
        ErrorCode.INVALID_ARGUMENT,
        `client ${config.clientId}: self_signed_tls_client_auth needs certificateThumbprint`,
      );
    }
  }

  return Object.freeze({
    ...config,
    grantTypes: config.grantTypes ?? DEFAULT_GRANT_TYPES,
    responseTypes: config.responseTypes ?? ['code'],
    tokenEndpointAuthMethod: authMethod,
    isPublic,
  });
}

/**
 * @typedef {Object} ClientRegistry
 * @property {(clientId: string) => (Client | undefined) | Promise<Client | undefined>} getClient
 */

/**
 * Build an in-memory registry from a static client list.
 *
 * @param {ClientConfig[]} clients
 * @returns {ClientRegistry}
 */
export function createClientRegistry(clients) {
  if (!isArray(clients)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'createServer requires a clients array (or a custom registry)');
  }
  /** @type {Map<string, Client>} */
  const byId = new Map();
  for (const client of clients) {
    const defined = defineClient(client);
    if (byId.has(defined.clientId)) {
      throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, `duplicate clientId ${JSON.stringify(defined.clientId)}`);
    }
    byId.set(defined.clientId, defined);
  }
  return {
    getClient(clientId) {
      return byId.get(clientId);
    },
  };
}

/**
 * Accept either a ready registry (an object with `getClient`) or a static
 * client list and return a registry.
 *
 * @param {ClientRegistry | ClientConfig[]} clientsOrRegistry
 * @returns {ClientRegistry}
 */
export function resolveRegistry(clientsOrRegistry) {
  if (
    isObject(clientsOrRegistry) &&
    typeof (/** @type {ClientRegistry} */ (clientsOrRegistry).getClient) === 'function'
  ) {
    return /** @type {ClientRegistry} */ (clientsOrRegistry);
  }
  return createClientRegistry(/** @type {ClientConfig[]} */ (clientsOrRegistry));
}
