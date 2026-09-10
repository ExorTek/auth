/**
 * `@exortek/oidc/provider` — the **OpenID Provider** (OP).
 *
 * Turns an `@exortek/oauth2` authorization server into an OpenID Provider:
 * `id_token` issuance (signed with the configured JWKS), the discovery
 * document (`/.well-known/openid-configuration`, OIDC Discovery 1.0), and
 * the UserInfo endpoint (OIDC Core §5.3).
 *
 * The handlers are scaffolded — configuration validation is real; the
 * `discoveryHandler` / `userinfoHandler` bodies throw `NOT_IMPLEMENTED`
 * until the endpoint pipeline lands.
 */
import { isNonEmptyString, isObject } from '@exortek/shared/predicates';
import { invalidArgument, notImplemented } from '../internal/errors.js';

/**
 * @typedef {object} OidcProviderClaims
 * @property {string[]} [supported] Every claim this OP can assert.
 * @property {string[]} [id_token]  Claims embedded in the `id_token`.
 * @property {string[]} [userinfo]  Claims returned from the UserInfo endpoint.
 */

/**
 * @typedef {object} OidcProviderConfig
 * @property {string}  issuer  This OP's issuer identifier (an https URL).
 * @property {object}  jwks    The signing key set (from `@exortek/jwk`).
 * @property {object}  store   Backing store for codes / grants / subjects.
 * @property {OidcProviderClaims} [claims] Claim policy for id_token / UserInfo.
 */

/**
 * Create an OpenID Provider.
 *
 * @param {OidcProviderConfig} config
 * @returns {{
 *   issuer: string,
 *   discoveryHandler: () => never,
 *   userinfoHandler: () => never,
 * }}
 */
export function createProvider(config) {
  if (!isObject(config)) {
    invalidArgument('createProvider(config): config must be an object.');
  }
  const { issuer, jwks, store } = config;

  if (!isNonEmptyString(issuer)) {
    invalidArgument('createProvider(config): `issuer` must be a non-empty string.');
  }
  if (!isObject(jwks)) {
    invalidArgument('createProvider(config): `jwks` must be a key set object.');
  }
  if (!isObject(store)) {
    invalidArgument('createProvider(config): `store` must be an object.');
  }
  if (config.claims !== undefined && !isObject(config.claims)) {
    invalidArgument('createProvider(config): `claims` must be an object when provided.');
  }

  return {
    issuer,

    /**
     * Framework-agnostic handler serving `/.well-known/openid-configuration`.
     * @returns {never}
     */
    discoveryHandler() {
      return notImplemented('createProvider().discoveryHandler');
    },

    /**
     * Framework-agnostic handler serving the UserInfo endpoint.
     * @returns {never}
     */
    userinfoHandler() {
      return notImplemented('createProvider().userinfoHandler');
    },
  };
}
