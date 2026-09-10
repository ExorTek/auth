/**
 * `@exortek/oidc/client` — the OpenID Connect **relying party** (SSO).
 *
 * A thin identity facade over `@exortek/oauth2`. Rather than a provider
 * preset, you point the client at an `issuer` and it discovers the
 * endpoints (`/.well-known/openid-configuration`), runs the OAuth 2.1
 * authorization-code flow with mandatory PKCE / `state` / `nonce`, and —
 * because the request always carries the `openid` scope — verifies the
 * returned `id_token` end to end (`iss` / `aud` / `nonce` / `exp`, `azp`,
 * `at_hash`, per OIDC Core §3.1.3.7) and layers UserInfo on top.
 *
 * All of that machinery already lives in `@exortek/oauth2`
 * (`defineProvider({ discover: true })` + `createOAuth`); this module is
 * the OIDC-shaped surface over it and does not reimplement discovery or
 * token verification.
 */
import { createOAuth, defineProvider } from '@exortek/oauth2';
import { decode } from '@exortek/jwt';
import { isArray, isNonEmptyString, isObject } from '@exortek/shared/predicates';

import { invalidArgument } from '../internal/errors.js';
import { buildEndSessionUrl } from '../internal/logout.js';
import { resolveIssuerMetadata } from '../internal/issuer-discovery.js';

/**
 * Standard OIDC claim projection. A relying party consumes the registered
 * claims verbatim; the normalization simply surfaces the common ones with
 * camelCase names while `handleCallback` also returns the raw claim set.
 *
 * @param {Record<string, unknown>} raw
 * @returns {{ sub: string, email?: string, emailVerified?: boolean, name?: string, picture?: string }}
 */
function mapStandardClaims(raw) {
  return {
    sub: /** @type {string} */ (raw.sub),
    email: /** @type {string | undefined} */ (raw.email),
    emailVerified: /** @type {boolean | undefined} */ (raw.email_verified),
    name: /** @type {string | undefined} */ (raw.name),
    picture: /** @type {string | undefined} */ (raw.picture),
  };
}

/** Map the camelCase OIDC auth-request options onto their wire names. */
const AUTH_PARAM_NAMES = {
  prompt: 'prompt',
  loginHint: 'login_hint',
  maxAge: 'max_age',
  acrValues: 'acr_values',
  uiLocales: 'ui_locales',
};

/**
 * @typedef {object} OidcClientConfig
 * @property {string}   issuer         The OpenID Provider's issuer identifier.
 * @property {string}   clientId       This relying party's client id.
 * @property {string}   [clientSecret] Client secret for confidential clients.
 * @property {string}   redirectUri    Registered redirect URI for the callback.
 * @property {string[]} [scope]        Requested scopes; `openid` is enforced.
 * @property {string[]} [idTokenAlgs]  Signature alg allowlist for the id_token.
 * @property {string|number} [clockTolerance]  Leeway for `exp`/`nbf`/`iat`.
 * @property {import('@exortek/jwks').RemoteJWKSOptions} [jwksOptions]  Forwarded to the id_token JWKS resolver.
 * @property {string} [endSessionEndpoint]  RP-Initiated Logout endpoint; auto-discovered from OP metadata when omitted.
 * @property {typeof fetch} [fetch]          Override used only for the logout-endpoint metadata fetch (tests / proxies).
 * @property {{ set: Function, get: Function, delete: Function }} [store]  Flow-session store keyed by `state`.
 */

/**
 * Create an OpenID Connect relying-party client.
 *
 * @param {OidcClientConfig} config
 */
export function createClient(config) {
  if (!isObject(config)) {
    invalidArgument('createClient(config): config must be an object.');
  }
  const { issuer, clientId, clientSecret, redirectUri } = config;

  if (!isNonEmptyString(issuer)) {
    invalidArgument('createClient(config): `issuer` must be a non-empty string.');
  }
  if (!isNonEmptyString(clientId)) {
    invalidArgument('createClient(config): `clientId` must be a non-empty string.');
  }
  if (!isNonEmptyString(redirectUri)) {
    invalidArgument('createClient(config): `redirectUri` must be a non-empty string.');
  }
  if (config.scope !== undefined && (!isArray(config.scope) || !config.scope.every(isNonEmptyString))) {
    invalidArgument('createClient(config): `scope` must be an array of non-empty strings.');
  }
  if (
    config.idTokenAlgs !== undefined &&
    (!isArray(config.idTokenAlgs) || !config.idTokenAlgs.every(isNonEmptyString))
  ) {
    invalidArgument('createClient(config): `idTokenAlgs` must be an array of non-empty strings.');
  }

  // `autoOpenidScope` (default true in defineProvider) prepends `openid`, so a
  // caller can never accidentally drop the scope that makes this OIDC.
  const providerFactory = defineProvider({
    id: 'oidc',
    kind: 'oidc',
    discover: true,
    issuer,
    idTokenAlgs: config.idTokenAlgs,
    jwksOptions: config.jwksOptions,
    mapUser: mapStandardClaims,
  });
  const provider = providerFactory({
    clientId,
    clientSecret,
    scope: config.scope,
    redirectUri,
  });

  const oauth = createOAuth({
    providers: [provider],
    store: config.store,
    security: config.clockTolerance === undefined ? {} : { clockTolerance: config.clockTolerance },
  });

  return {
    issuer,
    clientId,

    /**
     * Build the authorization-request URL (PKCE / `state` / `nonce` handled
     * by the oauth2 hub) with the OIDC auth-request parameters threaded in.
     *
     * @param {{ scope?: string[], prompt?: string, loginHint?: string, maxAge?: string|number, acrValues?: string, uiLocales?: string, params?: Record<string,string> }} [options]
     * @returns {Promise<{ url: string, session: string }>}
     */
    async authorize(options = {}) {
      /** @type {Record<string, string>} */
      const params = { ...options.params };
      for (const [key, wire] of Object.entries(AUTH_PARAM_NAMES)) {
        const value = /** @type {Record<string, unknown>} */ (options)[key];
        if (value !== undefined) {
          params[wire] = String(value);
        }
      }
      const { url, session } = await oauth.authorize('oidc', { scope: options.scope, params });
      return { url, session };
    },

    /**
     * Complete the flow: validate the callback, exchange the code, verify the
     * `id_token`, and fetch UserInfo. Signature / `nonce` / `iss` / `aud`
     * are already checked inside the oauth2 hub; `decode` here only reads the
     * now-trusted payload (no second network hop).
     *
     * @param {Record<string, unknown>} query   the callback query params
     * @param {{ session?: string }} [options]
     * @returns {Promise<{ idToken: string, claims: Record<string, unknown>, userinfo: Record<string, unknown>, user: object, tokens: Record<string, unknown>, warnings: object[] }>}
     */
    async handleCallback(query, options = {}) {
      const { tokens, user, warnings } = await oauth.callback('oidc', query, { session: options.session });
      const idToken = /** @type {string} */ (tokens.id_token);
      return {
        idToken,
        claims: decode(idToken).payload,
        userinfo: /** @type {Record<string, unknown>} */ (user).raw,
        user,
        tokens,
        warnings,
      };
    },

    /**
     * Build the RP-Initiated Logout URL (OIDC RP-Initiated Logout 1.0). The
     * issuer's `end_session_endpoint` is taken from `config.endSessionEndpoint`
     * when set, else resolved from the OP metadata.
     *
     * @param {{ idTokenHint: string, postLogoutRedirectUri?: string, state?: string, logoutHint?: string, uiLocales?: string }} params
     * @returns {Promise<string>}
     */
    async endSessionUrl(params = /** @type {any} */ ({})) {
      if (!isObject(params) || !isNonEmptyString(params.idTokenHint)) {
        invalidArgument('endSessionUrl(params): `idTokenHint` must be a non-empty string.');
      }
      let endpoint = config.endSessionEndpoint;
      if (!isNonEmptyString(endpoint)) {
        const meta = await resolveIssuerMetadata(issuer, { fetchImpl: config.fetch });
        endpoint = /** @type {string} */ (meta.end_session_endpoint);
        if (!isNonEmptyString(endpoint)) {
          invalidArgument(`endSessionUrl: issuer ${issuer} advertises no end_session_endpoint.`);
        }
      }
      return buildEndSessionUrl(endpoint, {
        idTokenHint: params.idTokenHint,
        postLogoutRedirectUri: params.postLogoutRedirectUri,
        state: params.state,
        clientId,
        logoutHint: params.logoutHint,
        uiLocales: params.uiLocales,
      });
    },

    /**
     * Exchange a refresh token for fresh tokens (RFC 6749 §6).
     * @param {string} refreshToken
     * @returns {Promise<Record<string, unknown>>}
     */
    refresh(refreshToken) {
      return oauth.refresh('oidc', refreshToken);
    },

    /**
     * Revoke an access or refresh token (RFC 7009).
     * @param {string} token
     * @param {string} [tokenTypeHint]
     * @returns {Promise<Record<string, unknown>>}
     */
    revoke(token, tokenTypeHint) {
      return oauth.revoke('oidc', token, tokenTypeHint);
    },
  };
}
