/**
 * `createOAuth` — the central multi-provider hub and the blessed
 * "connect to an auth server" path (PLAN.md Decision #1: no generic
 * `./client`). Providers are imported from their subpaths and passed in
 * as descriptors; the adapter owns the cross-cutting config (`baseUrl`,
 * `store`, `security` defaults) and drives every provider uniformly by
 * name. There is one API — a single provider is just a one-element
 * `createOAuth`.
 */
import { parseDuration } from '@exortek/shared/duration';
import { isNonEmptyString, isObject, isFunction } from '@exortek/shared/predicates';

import { ErrorCode, OAuth2Error } from './internal/errors.js';
import { resolveRedirectUri } from './internal/redirect-uri.js';
import { serializeSession, deserializeSession } from './internal/session.js';
import { postForm } from './internal/http.js';
import { buildAuthorization, handleCallback, resolveEndpoints } from './providers/_base.js';

const DEFAULT_MAX_AUTH_AGE = '10m';

/**
 * @typedef {Object} OAuthConfig
 * @property {string} baseUrl                       app origin, e.g. `https://app.com`
 * @property {string} callback                      callback template, e.g. `/auth/{provider}/callback`
 * @property {SessionStore} [store]                 optional server-side session store (keyed by `state`)
 * @property {{ maxAuthAge?: string|number, clockTolerance?: string|number }} [security]
 * @property {ResolvedProvider[]} providers         provider descriptors from `./providers/*`
 *
 * @typedef {Object} SessionStore
 * @property {(key: string, value: string, ttlMs: number) => unknown} set
 * @property {(key: string) => (string | null | undefined) | Promise<string | null | undefined>} get
 * @property {(key: string) => unknown} delete
 *
 * @typedef {import('./providers/_base.js').ResolvedProvider} ResolvedProvider
 */

/**
 * @param {OAuthConfig} config
 */
export function createOAuth(config) {
  if (!isObject(config)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'createOAuth requires a config object');
  }
  const { baseUrl, callback, store, security = {}, providers } = config;

  if (!Array.isArray(providers) || providers.length === 0) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'createOAuth requires a non-empty providers array');
  }
  if (store !== undefined && !isStore(store)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'store must expose set / get / delete');
  }

  const maxAuthAgeMs = parseDuration(security.maxAuthAge ?? DEFAULT_MAX_AUTH_AGE);
  const clockTolerance = security.clockTolerance;

  /** @type {Map<string, ResolvedProvider & { _redirectUri: string }>} */
  const registry = new Map();
  for (const provider of providers) {
    if (!isObject(provider) || provider.__oauth2Provider !== true) {
      throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'every entry in providers must come from a provider preset');
    }
    if (registry.has(provider.id)) {
      throw new OAuth2Error(
        ErrorCode.INVALID_ARGUMENT,
        `duplicate provider id ${JSON.stringify(provider.id)} — pass an { id } override to disambiguate`,
      );
    }
    provider._redirectUri = resolveRedirectUri(baseUrl, callback, provider.id, provider.redirectUriOverride);
    registry.set(provider.id, provider);
  }

  /**
   * @param {string} name
   * @returns {ResolvedProvider & { _redirectUri: string }}
   */
  function getProvider(name) {
    const provider = registry.get(name);
    if (!provider) {
      throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, `unknown provider ${JSON.stringify(name)}`);
    }
    return provider;
  }

  return {
    /**
     * Begin the flow. Returns the authorization `url` to redirect to and
     * an opaque `session` string to stash (cookie / store). When a store
     * is configured the session is also persisted keyed by `state`.
     *
     * @param {string} name
     * @param {{ scope?: string[], sessionBinding?: string, params?: Record<string,string> }} [options]
     */
    async authorize(name, options = {}) {
      const provider = getProvider(name);
      const { url, session, warnings } = await buildAuthorization(provider, {
        redirectUri: provider._redirectUri,
        scope: options.scope,
        sessionBinding: options.sessionBinding,
        params: options.params,
      });
      const serialized = serializeSession(session);
      if (store) {
        await store.set(session.state, serialized, maxAuthAgeMs);
      }
      return { url, session: serialized, warnings };
    },

    /**
     * Complete the flow. Provide the `session` returned by `authorize`,
     * or rely on the configured store to look it up by `query.state`.
     *
     * @param {string} name
     * @param {Record<string, unknown>} query   the callback query params
     * @param {{ session?: string, sessionBinding?: string }} [options]
     */
    async callback(name, query, options = {}) {
      const provider = getProvider(name);
      const session = await loadSession(query, options);
      return handleCallback(provider, {
        redirectUri: provider._redirectUri,
        query: query ?? {},
        session,
        sessionBinding: options.sessionBinding,
        clockTolerance,
      });
    },

    /**
     * Exchange a refresh token for a fresh access token (RFC 6749 §6).
     *
     * @param {string} name
     * @param {string} refreshToken
     * @returns {Promise<Record<string, unknown>>}
     */
    async refresh(name, refreshToken) {
      if (!isNonEmptyString(refreshToken)) {
        throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'refresh requires a refresh token');
      }
      const provider = getProvider(name);
      const ep = await resolveEndpoints(provider);
      return postForm(
        ep.tokenEndpoint,
        withClientAuth(provider, { grant_type: 'refresh_token', refresh_token: refreshToken }),
        { headers: provider.def.tokenHeaders, errorCode: ErrorCode.TOKEN_EXCHANGE_FAILED },
      );
    },

    /**
     * Revoke an access or refresh token (RFC 7009).
     *
     * @param {string} name
     * @param {string} token
     * @param {string} [tokenTypeHint]  `'access_token'` | `'refresh_token'`
     * @returns {Promise<Record<string, unknown>>}
     */
    async revoke(name, token, tokenTypeHint) {
      if (!isNonEmptyString(token)) {
        throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'revoke requires a token');
      }
      const provider = getProvider(name);
      const ep = await resolveEndpoints(provider);
      if (!isNonEmptyString(ep.revocationEndpoint)) {
        throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, `provider ${name} has no revocation endpoint`);
      }
      /** @type {Record<string,string>} */
      const params = { token };
      if (isNonEmptyString(tokenTypeHint)) {
        params.token_type_hint = tokenTypeHint;
      }
      return postForm(ep.revocationEndpoint, withClientAuth(provider, params), {
        headers: provider.def.tokenHeaders,
        errorCode: ErrorCode.TOKEN_EXCHANGE_FAILED,
      });
    },

    /** @returns {string[]} the registered provider ids */
    get providers() {
      return [...registry.keys()];
    },

    /** @param {string} name @returns {boolean} */
    has(name) {
      return registry.has(name);
    },
  };

  /**
   * @param {Record<string, unknown>} query
   * @param {{ session?: string }} options
   * @returns {Promise<import('./internal/session.js').FlowSession>}
   */
  async function loadSession(query, options) {
    if (isNonEmptyString(options.session)) {
      return deserializeSession(options.session);
    }
    if (store) {
      const key = query?.state;
      if (!isNonEmptyString(key)) {
        throw new OAuth2Error(ErrorCode.MISSING_STATE, 'callback has no `state` to look the session up by');
      }
      const stored = await store.get(key);
      if (!isNonEmptyString(stored)) {
        throw new OAuth2Error(ErrorCode.STATE_MISMATCH, 'no stored session for this `state` (expired or replayed)');
      }
      // Single-use: consume the stored session so a replayed callback fails.
      await store.delete(key);
      return deserializeSession(stored);
    }
    throw new OAuth2Error(ErrorCode.MISSING_STATE, 'no session provided and no store configured');
  }
}

/**
 * @param {ResolvedProvider} provider
 * @param {Record<string,string>} params
 * @returns {Record<string,string>}
 */
function withClientAuth(provider, params) {
  const out = { ...params, client_id: provider.clientId };
  if (isNonEmptyString(provider.clientSecret)) {
    out.client_secret = provider.clientSecret;
  }
  return out;
}

/** @param {unknown} store @returns {boolean} */
function isStore(store) {
  return isObject(store) && isFunction(store.set) && isFunction(store.get) && isFunction(store.delete);
}
