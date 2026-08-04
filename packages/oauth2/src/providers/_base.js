/**
 * `defineProvider` — the shared descriptor factory every provider preset
 * returns, plus the flow/security engine all providers run through.
 *
 * A preset is thin config: endpoints, capability flags, and a `mapUser`
 * projection. The two engine methods here — {@link buildAuthorization}
 * and {@link handleCallback} — own every cross-cutting security control,
 * enforced by default with no off-switch. Which controls apply is
 * derived from the provider `kind` (`oidc` vs `oauth2`), never applied
 * blindly.
 */
import { timingSafeEqual } from '@exortek/shared/timing-safe';
import { isNonEmptyString, isObject, isFunction } from '@exortek/shared/predicates';

import { ErrorCode, OAuth2Error } from '../internal/errors.js';
import { createPkcePair } from '../internal/pkce.js';
import { randomState, randomNonce } from '../internal/state.js';
import { postForm, getJson } from '../internal/http.js';
import { discover } from '../internal/discovery.js';
import { createJwksResolver, verifyIdToken } from '../internal/id-token.js';

/**
 * Non-fatal, degraded-but-not-blocked conditions. Surfaced in
 * `warnings[]` so the caller can react without the flow hard-failing.
 */
export const WarningCode = Object.freeze({
  PKCE_UNSUPPORTED: 'PKCE_UNSUPPORTED',
  SCOPE_NARROWED: 'SCOPE_NARROWED',
  EMAIL_UNVERIFIED: 'EMAIL_UNVERIFIED',
});

const DEFAULT_ID_TOKEN_ALGS = ['RS256', 'ES256', 'PS256'];

/**
 * Define a provider. Returns a factory that a consumer calls with their
 * per-app credentials; the result is passed to `createOAuth`.
 *
 * @param {ProviderDefinition} def
 * @returns {(appOptions: ProviderAppOptions) => ResolvedProvider}
 *
 * @typedef {Object} ProviderDefinition
 * @property {string} id                        default provider key (`'google'`)
 * @property {'oidc'|'oauth2'} kind
 * @property {string} [authorizationEndpoint]
 * @property {string} [tokenEndpoint]
 * @property {string} [userinfoEndpoint]
 * @property {string} [jwksUri]
 * @property {string} [revocationEndpoint]
 * @property {string | ((claimed: string) => boolean)} [issuer]   OIDC issuer — exact string, or a validator (multi-tenant)
 * @property {string} [expectedIssuer]          overrides `issuer` for the RFC 9207 `iss` param
 * @property {string} [emailEndpoint]           secondary email fetch (github)
 * @property {boolean} [discover]               resolve endpoints from `issuer` discovery
 * @property {boolean} [supportsPkce]           default true
 * @property {string[]} [defaultScopes]
 * @property {boolean} [autoOpenidScope]        prepend `openid` for OIDC (default true; Apple sets false)
 * @property {string[]} [idTokenAlgs]
 * @property {import('@exortek/jwks').RemoteJWKSOptions} [jwksOptions]  forwarded to the JWKS resolver
 * @property {'post'|'basic'} [clientAuth]                   client authentication at the token endpoint (default `post`)
 * @property {Record<string,string>} [authorizationParams]  extra static auth-request params
 * @property {Record<string,string>} [tokenHeaders]         extra headers on the token/refresh/revoke calls
 * @property {Record<string,string>} [userinfoHeaders]      extra headers on the userinfo/email calls (falls back to tokenHeaders)
 * @property {(raw: Record<string, unknown>, claims?: Record<string, unknown>) => NormalizedUserFields} mapUser
 *
 * @typedef {Object} ProviderAppOptions
 * @property {string} clientId
 * @property {string} [clientSecret]
 * @property {string[]} [scope]
 * @property {string} [redirectUri]
 * @property {string} [id]
 *
 * @typedef {Object} NormalizedUserFields
 * @property {string} sub
 * @property {string} [email]
 * @property {boolean} [emailVerified]
 * @property {string} [name]
 * @property {string} [picture]
 */
export function defineProvider(def) {
  if (!isObject(def) || !isNonEmptyString(def.id) || (def.kind !== 'oidc' && def.kind !== 'oauth2')) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'defineProvider requires an { id, kind } definition');
  }
  if (!isFunction(def.mapUser)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, `provider ${def.id} must supply a mapUser function`);
  }

  return function createProvider(appOptions = {}) {
    if (!isNonEmptyString(appOptions.clientId)) {
      throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, `provider ${def.id} requires a clientId`);
    }
    return {
      __oauth2Provider: true,
      id: isNonEmptyString(appOptions.id) ? appOptions.id : def.id,
      kind: def.kind,
      def,
      clientId: appOptions.clientId,
      clientSecret: appOptions.clientSecret,
      scope: Array.isArray(appOptions.scope) ? appOptions.scope : undefined,
      redirectUriOverride: appOptions.redirectUri,
      /** @type {ResolvedEndpoints | null} */
      _endpoints: null,
      /** @type {ReturnType<typeof createJwksResolver> | null} */
      _jwks: null,
    };
  };
}

/**
 * @typedef {Object} ResolvedEndpoints
 * @property {string} authorizationEndpoint
 * @property {string} tokenEndpoint
 * @property {string} [userinfoEndpoint]
 * @property {string} [jwksUri]
 * @property {string} [revocationEndpoint]
 * @property {string} [issuer]
 */

/**
 * Resolve (and cache on the provider) the endpoint set — from discovery
 * when `def.discover`, otherwise from the static preset. Explicit preset
 * endpoints always win over discovered ones.
 *
 * @param {ResolvedProvider} provider
 * @returns {Promise<ResolvedEndpoints>}
 */
export async function resolveEndpoints(provider) {
  if (provider._endpoints) {
    return provider._endpoints;
  }
  const { def } = provider;

  /** @type {ResolvedEndpoints} */
  let ep;
  if (def.discover) {
    if (!isNonEmptyString(def.issuer)) {
      throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, `provider ${provider.id} sets discover but has no issuer`);
    }
    const d = await discover(def.issuer);
    ep = {
      authorizationEndpoint: def.authorizationEndpoint ?? d.authorizationEndpoint,
      tokenEndpoint: def.tokenEndpoint ?? d.tokenEndpoint,
      userinfoEndpoint: def.userinfoEndpoint ?? d.userinfoEndpoint,
      jwksUri: def.jwksUri ?? d.jwksUri,
      revocationEndpoint: def.revocationEndpoint ?? d.revocationEndpoint,
      issuer: def.issuer,
    };
  } else {
    if (!isNonEmptyString(def.authorizationEndpoint) || !isNonEmptyString(def.tokenEndpoint)) {
      throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, `provider ${provider.id} is missing its endpoints`);
    }
    ep = {
      authorizationEndpoint: def.authorizationEndpoint,
      tokenEndpoint: def.tokenEndpoint,
      userinfoEndpoint: def.userinfoEndpoint,
      jwksUri: def.jwksUri,
      revocationEndpoint: def.revocationEndpoint,
      issuer: def.issuer,
    };
  }

  provider._endpoints = ep;
  return ep;
}

/**
 * Build the authorization-request URL and the flow session.
 *
 * @param {ResolvedProvider} provider
 * @param {{ redirectUri: string, scope?: string[], sessionBinding?: string, params?: Record<string,string>, jwksOptions?: object }} opts
 * @returns {Promise<{ url: string, session: import('../internal/session.js').FlowSession, warnings: Warning[] }>}
 */
export async function buildAuthorization(provider, opts) {
  const ep = await resolveEndpoints(provider);
  /** @type {Warning[]} */
  const warnings = [];

  const state = randomState();
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: provider.clientId,
    redirect_uri: opts.redirectUri,
    state,
    scope: resolveScopes(provider, opts.scope).join(' '),
  });

  /** @type {import('../internal/session.js').FlowSession} */
  const session = { provider: provider.id, state, createdAt: Date.now() };

  // PKCE S256 always, unless the provider genuinely rejects
  // it, in which case we degrade loudly.
  if (provider.def.supportsPkce === false) {
    warnings.push(
      warn(WarningCode.PKCE_UNSUPPORTED, `${provider.id} does not support PKCE; relying on state + exact redirect_uri`),
    );
  } else {
    const pkce = createPkcePair();
    params.set('code_challenge', pkce.codeChallenge);
    params.set('code_challenge_method', pkce.codeChallengeMethod);
    session.codeVerifier = pkce.codeVerifier;
  }

  // OIDC replay nonce.
  if (provider.kind === 'oidc') {
    const nonce = randomNonce();
    params.set('nonce', nonce);
    session.nonce = nonce;
  }

  // bind to the initiating user's session when supplied.
  if (isNonEmptyString(opts.sessionBinding)) {
    session.sessionBinding = opts.sessionBinding;
  }

  for (const [k, v] of Object.entries(provider.def.authorizationParams ?? {})) {
    params.set(k, v);
  }
  for (const [k, v] of Object.entries(opts.params ?? {})) {
    params.set(k, v);
  }

  return { url: `${ep.authorizationEndpoint}?${params.toString()}`, session, warnings };
}

/**
 * Validate the callback, exchange the code, verify the id_token (OIDC),
 * resolve and normalize the user.
 *
 * @param {ResolvedProvider} provider
 * @param {{
 *   redirectUri: string,
 *   query: Record<string, unknown>,
 *   session: import('../internal/session.js').FlowSession,
 *   sessionBinding?: string,
 *   clockTolerance?: string|number,
 * }} opts
 * @returns {Promise<{ tokens: Record<string, unknown>, user: NormalizedUser, warnings: Warning[] }>}
 */
export async function handleCallback(provider, opts) {
  const { query, session, redirectUri } = opts;
  /** @type {Warning[]} */
  const warnings = [];

  // the provider bounced back an error, not a code.
  if (isNonEmptyString(query.error)) {
    const desc = isNonEmptyString(query.error_description) ? `: ${query.error_description}` : '';
    throw new OAuth2Error(ErrorCode.PROVIDER_ERROR, `${provider.id} returned ${query.error}${desc}`, {
      details: { error: query.error, error_description: query.error_description },
    });
  }

  if (!isObject(session) || !isNonEmptyString(session.state)) {
    throw new OAuth2Error(ErrorCode.MISSING_STATE, 'callback has no flow session to validate against');
  }

  // COAT — the session must belong to the provider whose
  // callback this is.
  if (session.provider !== provider.id) {
    throw new OAuth2Error(
      ErrorCode.CONTEXT_MISMATCH,
      `flow session was started for ${session.provider}, not ${provider.id}`,
    );
  }

  // CSRF: state generated and verified, constant-time.
  if (!isNonEmptyString(query.state) || !safeEqual(query.state, session.state)) {
    throw new OAuth2Error(ErrorCode.STATE_MISMATCH, 'callback `state` does not match the flow session');
  }

  // the same user who started the flow must finish it.
  if (session.sessionBinding !== undefined) {
    if (!isNonEmptyString(opts.sessionBinding) || !safeEqual(opts.sessionBinding, session.sessionBinding)) {
      throw new OAuth2Error(ErrorCode.SESSION_MISMATCH, 'callback session binding does not match the flow session');
    }
  }

  const ep = await resolveEndpoints(provider);

  // RFC 9207 `iss` response param, exact match when present.
  if (query.iss !== undefined) {
    const expected = provider.def.expectedIssuer ?? ep.issuer;
    if (isNonEmptyString(expected) && query.iss !== expected) {
      throw new OAuth2Error(ErrorCode.ISSUER_MISMATCH, `callback iss ${JSON.stringify(query.iss)} does not match`);
    }
  }

  if (!isNonEmptyString(query.code)) {
    throw new OAuth2Error(ErrorCode.PROVIDER_ERROR, `${provider.id} callback is missing the authorization code`);
  }

  // token exchange replays the exact redirect_uri.
  /** @type {Record<string, string>} */
  const tokenParams = {
    grant_type: 'authorization_code',
    code: query.code,
    redirect_uri: redirectUri,
  };
  if (session.codeVerifier) {
    tokenParams.code_verifier = session.codeVerifier;
  }
  const { params: authedParams, headers: authHeaders } = applyClientAuth(provider, tokenParams);

  const tokens = await postForm(ep.tokenEndpoint, authedParams, {
    headers: { ...provider.def.tokenHeaders, ...authHeaders },
    errorCode: ErrorCode.TOKEN_EXCHANGE_FAILED,
  });

  // granted scope narrower than requested → warn, not fail.
  const narrowed = narrowedScopes(resolveScopes(provider, undefined), tokens.scope);
  if (narrowed.length > 0) {
    warnings.push(warn(WarningCode.SCOPE_NARROWED, `provider did not grant: ${narrowed.join(' ')}`));
  }

  // OIDC id_token verification.
  /** @type {Record<string, unknown> | undefined} */
  let idClaims;
  if (provider.kind === 'oidc') {
    if (!isNonEmptyString(tokens.id_token)) {
      throw new OAuth2Error(ErrorCode.ID_TOKEN_INVALID, `${provider.id} did not return an id_token`);
    }
    if (!isNonEmptyString(ep.jwksUri)) {
      throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, `provider ${provider.id} is OIDC but has no jwks_uri`);
    }
    provider._jwks ??= createJwksResolver(ep.jwksUri, provider.def.jwksOptions);
    const verified = await verifyIdToken(tokens.id_token, {
      jwks: provider._jwks,
      issuer: ep.issuer,
      clientId: provider.clientId,
      nonce: session.nonce,
      clockTolerance: opts.clockTolerance,
      algs: provider.def.idTokenAlgs ?? DEFAULT_ID_TOKEN_ALGS,
      accessToken: isNonEmptyString(tokens.access_token) ? tokens.access_token : undefined,
      code: query.code,
    });
    idClaims = verified.claims;
  }

  // Resolve the user. Start from id_token claims (Apple has no userinfo)
  // and layer the userinfo endpoint on top when there is one.
  /** @type {Record<string, unknown>} */
  let raw = idClaims ? { ...idClaims } : {};
  if (isNonEmptyString(ep.userinfoEndpoint) && isNonEmptyString(tokens.access_token)) {
    const info = await getJson(
      ep.userinfoEndpoint,
      { token: tokens.access_token },
      { headers: provider.def.userinfoHeaders ?? provider.def.tokenHeaders, errorCode: ErrorCode.USERINFO_FAILED },
    );
    // the userinfo subject must be the id_token subject.
    if (idClaims && isNonEmptyString(info.sub) && info.sub !== idClaims.sub) {
      throw new OAuth2Error(ErrorCode.SUB_MISMATCH, 'userinfo sub does not match the id_token sub');
    }
    raw = { ...raw, ...info };

    // github-style secondary email fetch.
    if (isNonEmptyString(provider.def.emailEndpoint)) {
      const emails = await getJson(
        provider.def.emailEndpoint,
        { token: tokens.access_token },
        { headers: provider.def.userinfoHeaders ?? provider.def.tokenHeaders, errorCode: ErrorCode.USERINFO_FAILED },
      );
      raw.emails = emails;
    }
  }

  const mapped = provider.def.mapUser(raw, idClaims);
  if (!isNonEmptyString(mapped.sub)) {
    throw new OAuth2Error(ErrorCode.SUB_MISMATCH, `${provider.id} did not yield a stable subject id`);
  }

  // surface an unverified email rather than trusting it.
  if (isNonEmptyString(mapped.email) && mapped.emailVerified === false) {
    warnings.push(warn(WarningCode.EMAIL_UNVERIFIED, `${provider.id} reports the email as unverified`));
  }

  /** @type {NormalizedUser} */
  const user = { ...mapped, provider: provider.id, raw };
  return { tokens, user, warnings };
}

// SCOPES

/**
 * @param {ResolvedProvider} provider
 * @param {string[] | undefined} override
 * @returns {string[]}
 */
function resolveScopes(provider, override) {
  const base = override ?? provider.scope ?? provider.def.defaultScopes ?? [];
  // OIDC issues an id_token off the `openid` scope. A provider that
  // rejects an explicit `openid` (Apple) opts out with autoOpenidScope.
  if (provider.kind === 'oidc' && provider.def.autoOpenidScope !== false && !base.includes('openid')) {
    return ['openid', ...base];
  }
  return base;
}

/**
 * @param {string[]} requested
 * @param {unknown} grantedScope  the token response `scope` (space-delimited)
 * @returns {string[]}
 */
function narrowedScopes(requested, grantedScope) {
  if (!isNonEmptyString(grantedScope)) {
    return [];
  }
  const granted = new Set(grantedScope.split(/\s+/));
  return requested.filter(s => s !== 'openid' && !granted.has(s));
}

/** Length-safe string equality on the UTF-8 bytes. */
function safeEqual(a, b) {
  return timingSafeEqual(Buffer.from(String(a), 'utf8'), Buffer.from(String(b), 'utf8'));
}

/**
 * Apply client authentication to a set of token-endpoint params. The
 * default is `client_secret_post` (credentials in the body); a provider
 * can declare `clientAuth: 'basic'` to send HTTP Basic instead (some
 * providers, e.g. X/Twitter, require it). `client_id` always rides in
 * the body — providers accept it there regardless of the auth style.
 *
 * @param {ResolvedProvider} provider
 * @param {Record<string,string>} params
 * @returns {{ params: Record<string,string>, headers: Record<string,string> }}
 */
export function applyClientAuth(provider, params) {
  const out = { ...params, client_id: provider.clientId };
  /** @type {Record<string,string>} */
  const headers = {};
  if (isNonEmptyString(provider.clientSecret)) {
    if (provider.def.clientAuth === 'basic') {
      const creds = Buffer.from(`${provider.clientId}:${provider.clientSecret}`).toString('base64');
      headers.authorization = `Basic ${creds}`;
    } else {
      out.client_secret = provider.clientSecret;
    }
  }
  return { params: out, headers };
}

/**
 * @param {string} code
 * @param {string} message
 * @returns {Warning}
 */
function warn(code, message) {
  return { code, message };
}

/**
 * @typedef {Object} Warning
 * @property {string} code
 * @property {string} message
 *
 * @typedef {NormalizedUserFields & { provider: string, raw: Record<string, unknown> }} NormalizedUser
 * @typedef {ReturnType<ReturnType<typeof defineProvider>>} ResolvedProvider
 */
