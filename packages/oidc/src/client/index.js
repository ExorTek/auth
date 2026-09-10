/**
 * `@exortek/oidc/client` — the OpenID Connect **relying party** (SSO).
 *
 * A thin identity layer over `@exortek/oauth2`'s authorization-code flow:
 * it drives the same PKCE / `state` / `nonce` machinery, then adds the
 * OIDC Core guarantees on top — mandatory `openid` scope, `id_token`
 * validation (`iss` / `aud` / `exp` / `nonce`, per OIDC Core §3.1.3.7),
 * and a UserInfo fetch.
 *
 * The flow methods are scaffolded — configuration validation is real; the
 * `createAuthUrl` / `handleCallback` bodies throw `NOT_IMPLEMENTED` until
 * the callback pipeline lands.
 */
import { randomNonce, randomState } from '@exortek/oauth2';
import { isArray, isNonEmptyString, isObject } from '@exortek/shared/predicates';
import { invalidArgument, notImplemented } from '../internal/errors.js';

/**
 * @typedef {object} OidcClientConfig
 * @property {string}   issuer        The OpenID Provider's issuer identifier.
 * @property {string}   clientId      This relying party's client id.
 * @property {string}   [clientSecret] Client secret for confidential clients.
 * @property {string}   redirectUri   Registered redirect URI for the callback.
 * @property {string[]} [scope]       Requested scopes; `openid` is enforced.
 */

/**
 * Create an OpenID Connect relying-party client.
 *
 * @param {OidcClientConfig} config
 * @returns {{
 *   issuer: string,
 *   clientId: string,
 *   scope: string[],
 *   createAuthUrl: (options?: object) => never,
 *   handleCallback: (params: object, options?: object) => Promise<never>,
 * }}
 */
export function createClient(config) {
  if (!isObject(config)) {
    invalidArgument('createClient(config): config must be an object.');
  }
  const { issuer, clientId, redirectUri } = config;

  if (!isNonEmptyString(issuer)) {
    invalidArgument('createClient(config): `issuer` must be a non-empty string.');
  }
  if (!isNonEmptyString(clientId)) {
    invalidArgument('createClient(config): `clientId` must be a non-empty string.');
  }
  if (!isNonEmptyString(redirectUri)) {
    invalidArgument('createClient(config): `redirectUri` must be a non-empty string.');
  }

  // OIDC Core §3.1.2.1 — `openid` is what turns an OAuth request into an
  // OpenID Connect one. Default to it, and never let a caller drop it.
  const requested = config.scope === undefined ? ['openid'] : config.scope;
  if (!isArray(requested) || !requested.every(isNonEmptyString)) {
    invalidArgument('createClient(config): `scope` must be an array of non-empty strings.');
  }
  const scope = requested.includes('openid') ? [...requested] : ['openid', ...requested];

  return {
    issuer,
    clientId,
    scope,

    /**
     * Build the authorization-request URL (with PKCE / `state` / `nonce`).
     * @returns {never}
     */
    createAuthUrl() {
      // `randomState` / `randomNonce` are wired now so the CSRF-nonce source
      // is settled; the URL assembly lands with the discovery pipeline.
      void randomState;
      void randomNonce;
      return notImplemented('createClient().createAuthUrl');
    },

    /**
     * Validate the callback, exchange the code, verify the `id_token`, and
     * fetch UserInfo.
     * @returns {Promise<never>}
     */
    async handleCallback() {
      return notImplemented('createClient().handleCallback');
    },
  };
}
