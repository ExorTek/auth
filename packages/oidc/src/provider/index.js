/**
 * `@exortek/oidc/provider` — the **OpenID Provider** (OP) add-ons.
 *
 * `@exortek/oauth2`'s authorization server (`@exortek/oauth2/server`) already
 * issues an `id_token` off the `openid` scope; what it has no first-class
 * answer for is the OIDC identity surface. `createProvider` supplies exactly
 * that, to mount **beside** your `createServer`:
 *
 *   - the OpenID discovery document (`/.well-known/openid-configuration`),
 *   - the UserInfo endpoint (OIDC Core §5.3),
 *   - the published JWKS,
 *   - and an `id_token` signer (`createIdTokenSigner`) so the server and this
 *     provider sign with the same key.
 *
 * RP-Initiated Logout and Session Management add their handlers in follow-up
 * work.
 */
import { createIdTokenSigner } from '@exortek/oauth2/server';
import { isArray, isNonEmptyString, isObject } from '@exortek/shared/predicates';

import { invalidArgument } from '../internal/errors.js';
import { buildDiscoveryDocument } from '../internal/discovery-doc.js';
import { buildUserInfo } from '../internal/userinfo.js';
import { isRegisteredPostLogoutUri, readIdTokenHint } from '../internal/logout.js';
import { checkSessionIframeHtml, computeSessionState } from '../internal/session.js';
import { htmlResponse, jsonResponse, normalizeRequest, redirectResponse } from '../internal/http-io.js';

const DEFAULT_SCOPES = ['openid', 'profile', 'email'];
const DEFAULT_CLAIMS_SUPPORTED = ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce'];

/**
 * @typedef {object} OidcProviderConfig
 * @property {string} issuer                       the OP issuer identifier (https URL).
 * @property {{ key: unknown, alg: string, kid?: string, expiresIn?: string|number }} signing  id_token signer.
 * @property {object[] | { keys: object[] }} [jwks]  public JWK Set to publish at `jwks_uri`.
 * @property {Record<string, string>} endpoints    endpoint URLs/paths to advertise (authorization + token required).
 * @property {{ supported?: string[], id_token?: string[], userinfo?: string[] }} [claims]  claim policy.
 * @property {string[]} [scopes]                    advertised scopes (default openid/profile/email).
 * @property {string[]} [authMethods]              token_endpoint_auth_methods_supported.
 * @property {{ resolve: (accessToken: string) => (Promise<{ sub: string, scope?: string|string[], claims?: Record<string, unknown> } | null> | { sub: string, scope?: string|string[], claims?: Record<string, unknown> } | null) }} [userinfo]  access-token resolver for the UserInfo endpoint.
 * @property {{ postLogoutRedirectUris?: string[], onLogout?: (ctx: { sub?: string, idTokenHint?: string }) => unknown }} [logout]  RP-Initiated Logout policy.
 * @property {{ cookieName?: string }} [session]  enable Session Management; `cookieName` names the OP browser-state cookie.
 */

/**
 * Create an OpenID Provider add-on.
 *
 * @param {OidcProviderConfig} config
 */
export function createProvider(config) {
  if (!isObject(config)) {
    invalidArgument('createProvider(config): config must be an object.');
  }
  const { issuer, signing, endpoints } = config;

  if (!isNonEmptyString(issuer)) {
    invalidArgument('createProvider(config): `issuer` must be a non-empty string.');
  }
  if (!isObject(signing) || signing.key === undefined || signing.key === null || !isNonEmptyString(signing.alg)) {
    invalidArgument('createProvider(config): `signing` must be { key, alg }.');
  }
  if (!isObject(endpoints) || !isNonEmptyString(endpoints.authorization) || !isNonEmptyString(endpoints.token)) {
    invalidArgument('createProvider(config): `endpoints` must include `authorization` and `token`.');
  }
  if (config.claims !== undefined && !isObject(config.claims)) {
    invalidArgument('createProvider(config): `claims` must be an object when provided.');
  }

  const claimsPolicy = config.claims ?? {};
  const scopes = isArray(config.scopes) ? config.scopes : DEFAULT_SCOPES;

  // Resolve every advertised endpoint to an absolute URL; default the two the
  // provider itself serves (userinfo + jwks) to conventional paths.
  const resolved = {
    authorization: toAbsolute(endpoints.authorization, issuer),
    token: toAbsolute(endpoints.token, issuer),
    userinfo: toAbsolute(endpoints.userinfo ?? '/userinfo', issuer),
    jwks: toAbsolute(endpoints.jwks ?? '/.well-known/jwks.json', issuer),
  };
  for (const optional of ['endSession', 'checkSession', 'revocation', 'introspection', 'registration']) {
    if (isNonEmptyString(endpoints[optional])) {
      resolved[optional] = toAbsolute(endpoints[optional], issuer);
    }
  }
  // Configuring logout auto-advertises the end-session endpoint at its
  // conventional path when the caller did not pin one.
  if (isObject(config.logout) && !resolved.endSession) {
    resolved.endSession = toAbsolute('/end_session', issuer);
  }
  // Likewise for Session Management's check-session iframe.
  if (isObject(config.session) && !resolved.checkSession) {
    resolved.checkSession = toAbsolute('/check_session', issuer);
  }

  const discoveryDoc = buildDiscoveryDocument({
    issuer,
    endpoints: resolved,
    scopes,
    claimsSupported: isArray(claimsPolicy.supported) ? claimsPolicy.supported : DEFAULT_CLAIMS_SUPPORTED,
    idTokenAlgs: [signing.alg],
    authMethods: config.authMethods,
  });

  const publicJwks = normalizeJwks(config.jwks);

  const idTokenSigner = createIdTokenSigner({
    signingKey: signing.key,
    alg: signing.alg,
    kid: signing.kid,
    expiresIn: signing.expiresIn,
  });

  return {
    issuer,
    idTokenSigner,

    /** The assembled discovery document (also served by `discoveryHandler`). */
    metadata() {
      return discoveryDoc;
    },

    /**
     * Serves `/.well-known/openid-configuration`. Cacheable.
     * @returns {(req?: object) => import('../internal/http-io.js').OidcResponse}
     */
    discoveryHandler() {
      return () => jsonResponse(200, discoveryDoc, { 'cache-control': 'public, max-age=3600' });
    },

    /**
     * Serves the published JWKS at `jwks_uri`. Cacheable.
     * @returns {(req?: object) => import('../internal/http-io.js').OidcResponse}
     */
    jwksHandler() {
      return () => jsonResponse(200, { keys: publicJwks }, { 'cache-control': 'public, max-age=3600' });
    },

    /**
     * Serves the UserInfo endpoint (OIDC Core §5.3). Requires `config.userinfo.
     * resolve` to turn a Bearer access token into `{ sub, scope, claims }`.
     * @returns {(req: object) => Promise<import('../internal/http-io.js').OidcResponse>}
     */
    userinfoHandler() {
      if (!isObject(config.userinfo) || typeof config.userinfo.resolve !== 'function') {
        invalidArgument('userinfoHandler(): config.userinfo.resolve must be a function.');
      }
      const resolve = config.userinfo.resolve;
      return async raw => {
        const req = normalizeRequest(raw);
        const token = bearerToken(req);
        if (!token) {
          return unauthorized('invalid_request', 'a Bearer access token is required');
        }
        let resolved;
        try {
          resolved = await resolve(token);
        } catch {
          resolved = null;
        }
        if (!isObject(resolved) || !isNonEmptyString(resolved.sub)) {
          return unauthorized('invalid_token', 'the access token is invalid or expired');
        }
        const grantedScopes = toScopeArray(resolved.scope);
        const body = buildUserInfo(resolved.sub, resolved.claims ?? {}, grantedScopes, claimsPolicy.userinfo);
        return jsonResponse(200, body, { 'cache-control': 'no-store', pragma: 'no-cache' });
      };
    },

    /**
     * Serves the RP-Initiated Logout endpoint (OIDC RP-Initiated Logout 1.0).
     * Validates `post_logout_redirect_uri` against the client's registered
     * URIs before redirecting; calls `config.logout.onLogout` (when given) to
     * clear the OP session.
     * @returns {(req: object) => Promise<import('../internal/http-io.js').OidcResponse>}
     */
    endSessionHandler() {
      const logout = isObject(config.logout) ? config.logout : {};
      const registered = isArray(logout.postLogoutRedirectUris) ? logout.postLogoutRedirectUris : [];
      const onLogout = typeof logout.onLogout === 'function' ? logout.onLogout : undefined;
      return async raw => {
        const req = normalizeRequest(raw);
        const idTokenHint = req.param('id_token_hint');
        const postLogout = req.param('post_logout_redirect_uri');
        const state = req.param('state');
        const hint = readIdTokenHint(idTokenHint, issuer);

        if (onLogout) {
          try {
            await onLogout({ sub: hint ? hint.sub : undefined, idTokenHint });
          } catch {
            // Session teardown is best-effort — never block the logout redirect.
          }
        }

        if (isNonEmptyString(postLogout)) {
          if (!isRegisteredPostLogoutUri(postLogout, registered)) {
            return jsonResponse(
              400,
              { error: 'invalid_request', error_description: 'post_logout_redirect_uri is not registered' },
              { 'cache-control': 'no-store' },
            );
          }
          const target = new URL(postLogout);
          if (isNonEmptyString(state)) {
            target.searchParams.set('state', state);
          }
          return redirectResponse(target.toString(), { 'cache-control': 'no-store' });
        }

        return jsonResponse(200, { logged_out: true }, { 'cache-control': 'no-store' });
      };
    },

    /**
     * Compute a `session_state` (OIDC Session Management §4.2) for an auth
     * response, from the client id, the RP's origin and the OP browser-state
     * value the OP set in the user's browser.
     *
     * @param {{ clientId: string, origin: string, opBrowserState: string, salt?: string }} input
     * @returns {string}
     */
    sessionState(input) {
      if (
        !isObject(input) ||
        !isNonEmptyString(input.clientId) ||
        !isNonEmptyString(input.origin) ||
        !isNonEmptyString(input.opBrowserState)
      ) {
        invalidArgument('sessionState(input): { clientId, origin, opBrowserState } are required.');
      }
      return computeSessionState(input);
    },

    /**
     * Serves the OP `check_session_iframe` document (OIDC Session Management
     * §4.2). Cacheable; reads the OP browser-state cookie named
     * `config.session.cookieName` (default `op_browser_state`).
     * @returns {(req?: object) => import('../internal/http-io.js').OidcResponse}
     */
    checkSessionHandler() {
      const cookieName = isObject(config.session) ? config.session.cookieName : undefined;
      const html = checkSessionIframeHtml({ cookieName });
      return () => htmlResponse(200, html, { 'cache-control': 'public, max-age=3600' });
    },
  };
}

/**
 * @param {string} value  absolute URL or a path resolved against `issuer`
 * @param {string} issuer
 * @returns {string}
 */
function toAbsolute(value, issuer) {
  if (/^https?:\/\//i.test(value)) {
    return value;
  }
  return new URL(value, issuer.endsWith('/') ? issuer : `${issuer}/`).toString();
}

/** @param {object[] | { keys: object[] } | undefined} jwks */
function normalizeJwks(jwks) {
  if (isArray(jwks)) {
    return jwks;
  }
  if (isObject(jwks) && isArray(jwks.keys)) {
    return jwks.keys;
  }
  return [];
}

/** @param {import('../internal/http-io.js').OidcRequest} req */
function bearerToken(req) {
  const auth = req.header('authorization');
  if (isNonEmptyString(auth) && auth.slice(0, 7).toLowerCase() === 'bearer ') {
    return auth.slice(7).trim();
  }
  // OIDC Core §5.3.1 also permits the token as an `access_token` form/query param.
  const param = req.param('access_token');
  return isNonEmptyString(param) ? param : undefined;
}

/** @param {string|string[]|undefined} scope */
function toScopeArray(scope) {
  if (isArray(scope)) {
    return scope;
  }
  if (isNonEmptyString(scope)) {
    return scope.split(/\s+/).filter(Boolean);
  }
  return [];
}

/**
 * @param {string} error
 * @param {string} description
 * @returns {import('../internal/http-io.js').OidcResponse}
 */
function unauthorized(error, description) {
  return jsonResponse(
    401,
    { error, error_description: description },
    { 'www-authenticate': `Bearer error="${error}", error_description="${description}"`, 'cache-control': 'no-store' },
  );
}
