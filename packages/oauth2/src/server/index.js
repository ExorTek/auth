/**
 * `createServer` — the authorization-server hub. Assembles the endpoint
 * handlers (metadata / authorize / token / revoke / introspect / PAR /
 * device) over a normalized request→response descriptor, so the same
 * server drives Fastify, Express, or a bare `node:http` listener through
 * the thin `./server/fastify` and `./server/express` adapters.
 *
 * Secure by default (PLAN Decision #0): PKCE S256 is required, `iss` is
 * always returned (RFC 9207), redirect URIs are exact-matched, and no
 * protection is a silent off-switch. The caller brings the client
 * registry, a token-issuer strategy, and a way to authenticate the
 * resource owner; the server brings the security.
 */
import { parseDuration } from '@exortek/shared/duration';
import { isArray, isFunction, isNonEmptyString, isObject } from '@exortek/shared/predicates';

import { ErrorCode, OAuth2Error } from '../internal/errors.js';
import { requireNonEmptyString } from '../internal/guards.js';
import { resolveRegistry } from './clients.js';
import { createAuthCodeStore, createRefreshStore, createParStore, createDeviceStore } from './stores.js';
import { createMetadataHandler } from './handlers/metadata.js';
import { createAuthorizeHandler } from './handlers/authorize.js';
import { createTokenHandler } from './handlers/token.js';
import { createRevokeHandler } from './handlers/revoke.js';
import { createIntrospectHandler } from './handlers/introspect.js';
import { createParHandler } from './handlers/par.js';
import { createDeviceHandler, createDeviceApproval } from './handlers/device.js';
import { applyFapiProfile } from './security/fapi.js';

export { defineClient, createClientRegistry, AUTH_METHODS } from './clients.js';
export { jwtIssuer } from './issuers/jwt.js';
export { pasetoIssuer } from './issuers/paseto.js';
export { ServerError, ProtocolError } from './errors.js';

const DEFAULT_GRANTS = ['authorization_code', 'refresh_token', 'client_credentials'];
const DEFAULT_AUTH_CODE_TTL = '1m';
const DEFAULT_PAR_TTL = '90s';

/**
 * @typedef {Object} ServerSecurity
 * @property {boolean} [requirePkce=true]         PKCE S256 required on the code grant
 * @property {string|number} [authorizationCodeTtl='1m']
 * @property {{ required?: boolean, algs?: string[], nonce?: boolean }} [dpop]   RFC 9449
 * @property {{ required?: boolean, ttl?: string|number }} [par]                 RFC 9126
 * @property {boolean} [fapi]                      FAPI 2.0 profile (bundles PAR + PKCE + DPoP/mTLS + iss)
 *
 * @typedef {Object} ServerConfig
 * @property {string} issuer                       AS issuer identifier (https, no trailing slash)
 * @property {import('./clients.js').ClientConfig[] | import('./clients.js').ClientRegistry} clients
 * @property {{ issue: Function, introspect: Function }} tokens   an issuer strategy (jwtIssuer / pasetoIssuer)
 * @property {string} [jwksUri]                    where the AS publishes its signing JWKS (advertised only)
 * @property {(req: import('./request.js').ServerRequest) => (UserAuthn | null) | Promise<UserAuthn | null>} authenticateUser
 * @property {string[]} [grants]                   allowed grant types (default code + refresh + client_credentials)
 * @property {string[]} [scopes]                   supported scopes (advertised; also the escalation ceiling)
 * @property {Partial<Endpoints>} [endpoints]      override the endpoint URLs advertised in metadata
 * @property {Partial<ServerStores>} [stores]      swap in Redis-backed stores
 * @property {ServerSecurity} [security]
 *
 * @typedef {Object} UserAuthn
 * @property {string} subject                      resource-owner identifier → `sub`
 * @property {number} [authTime]                   unix seconds of the authentication event (`auth_time`)
 *
 * @typedef {Object} Endpoints
 * @property {string} authorization
 * @property {string} token
 * @property {string} [introspection]
 * @property {string} [revocation]
 * @property {string} [par]
 * @property {string} [deviceAuthorization]
 *
 * @typedef {Object} ServerStores
 * @property {ReturnType<typeof createAuthCodeStore>} authCode
 * @property {ReturnType<typeof createRefreshStore>} refresh
 * @property {ReturnType<typeof createParStore>} par
 * @property {ReturnType<typeof createDeviceStore>} device
 *
 * @typedef {Object} ResolvedServerConfig
 * @property {string} issuer
 * @property {Endpoints} endpoints
 * @property {string} [jwksUri]
 * @property {string[]} grantTypes
 * @property {string[]} [scopes]
 * @property {string[]} authMethods
 * @property {string[]} [dpopAlgs]
 * @property {boolean} requirePar
 */

/**
 * @param {ServerConfig} config
 */
export function createServer(config) {
  if (!isObject(config)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'createServer requires a config object');
  }
  const issuer = requireNonEmptyString(config.issuer, 'issuer');
  assertHttpsIssuer(issuer);

  if (!isObject(config.tokens) || !isFunction(config.tokens.issue) || !isFunction(config.tokens.introspect)) {
    throw new OAuth2Error(
      ErrorCode.INVALID_ARGUMENT,
      'createServer requires a tokens issuer (jwtIssuer / pasetoIssuer)',
    );
  }
  if (!isFunction(config.authenticateUser)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'createServer requires an authenticateUser(req) hook');
  }

  const registry = resolveRegistry(config.clients);
  const security = isObject(config.security) ? config.security : {};
  const grantTypes = isArray(config.grants) ? config.grants : DEFAULT_GRANTS;
  const endpoints = resolveEndpoints(issuer, config.endpoints);

  const stores = {
    authCode: config.stores?.authCode ?? createAuthCodeStore(),
    refresh: config.stores?.refresh ?? createRefreshStore(),
    par: config.stores?.par ?? createParStore(),
    device: config.stores?.device ?? createDeviceStore(),
  };

  // FAPI 2.0 tightens several defaults at once (PLAN Tier C).
  const { fapi, requirePkce, requirePar, dpopRequired } = applyFapiProfile(security);

  /** @type {ResolvedServerConfig & { registry, tokens, stores, security, requirePkce, requirePar, dpopRequired, authenticateUser, authorizationCodeTtlMs, parTtlMs, fapi }} */
  const resolved = {
    issuer,
    endpoints,
    jwksUri: config.jwksUri,
    grantTypes,
    scopes: config.scopes,
    authMethods: collectAuthMethods(grantTypes),
    dpopAlgs: security.dpop?.algs ?? ['ES256', 'RS256', 'EdDSA'],
    requirePar,
    // Runtime-only fields (not part of the metadata-facing shape):
    registry,
    tokens: config.tokens,
    stores,
    security,
    requirePkce,
    dpopRequired,
    fapi,
    authenticateUser: config.authenticateUser,
    authorizationCodeTtlMs: parseDuration(security.authorizationCodeTtl ?? DEFAULT_AUTH_CODE_TTL),
    parTtlMs: parseDuration(security.par?.ttl ?? DEFAULT_PAR_TTL),
    authorizationDetailsTypes: config.authorizationDetailsTypes,
    jarm: config.jarm,
    deviceCodeTtlMs: config.device?.ttl !== undefined ? parseDuration(config.device.ttl) : undefined,
    deviceInterval: config.device?.interval,
    deviceVerificationUri: config.device?.verificationUri,
  };

  return {
    /** RFC 8414 authorization-server metadata document. */
    metadata: createMetadataHandler(resolved),

    /** Authorization endpoint (RFC 6749 §4.1.1) — code grant, PKCE-required. */
    authorize: createAuthorizeHandler(resolved),

    /** Token endpoint (RFC 6749 §3.2) — code / refresh / client_credentials grants. */
    token: createTokenHandler(resolved),

    /** Token revocation endpoint (RFC 7009). */
    revoke: createRevokeHandler(resolved),

    /** Token introspection endpoint (RFC 7662). */
    introspect: createIntrospectHandler(resolved),

    /** Pushed authorization request endpoint (RFC 9126). */
    par: createParHandler(resolved),

    /** Device authorization endpoint (RFC 8628). */
    deviceAuthorization: createDeviceHandler(resolved),

    /**
     * Device-approval API for the host's verification page — look up a
     * pending request by `user_code`, then `approve({ subject })` or
     * `deny()` it (RFC 8628 §3.3).
     */
    device: createDeviceApproval(resolved),

    /** @internal exposed for tests and the framework adapters */
    _config: resolved,
  };
}

// CONFIG RESOLUTION

/**
 * @param {string} issuer
 * @param {Partial<Endpoints>} [overrides]
 * @returns {Endpoints}
 */
function resolveEndpoints(issuer, overrides = {}) {
  const base = issuer.replace(/\/$/, '');
  return {
    authorization: overrides.authorization ?? `${base}/authorize`,
    token: overrides.token ?? `${base}/token`,
    introspection: overrides.introspection ?? `${base}/introspect`,
    revocation: overrides.revocation ?? `${base}/revoke`,
    par: overrides.par ?? `${base}/par`,
    deviceAuthorization: overrides.deviceAuthorization ?? `${base}/device_authorization`,
  };
}

/**
 * The token-endpoint auth methods this server advertises. Every method
 * the client-auth layer implements is offered; a client still only uses
 * the one its registration declares.
 *
 * @param {string[]} _grantTypes
 * @returns {string[]}
 */
function collectAuthMethods(_grantTypes) {
  return [
    'none',
    'client_secret_basic',
    'client_secret_post',
    'client_secret_jwt',
    'private_key_jwt',
    'tls_client_auth',
    'self_signed_tls_client_auth',
  ];
}

/**
 * The issuer identifier must be an `https` URL with no query or fragment
 * (RFC 8414 §2); `http://localhost` is tolerated for development, exactly
 * as the RP-side redirect_uri rule does.
 *
 * @param {string} issuer
 */
function assertHttpsIssuer(issuer) {
  let url;
  try {
    url = new URL(issuer);
  } catch {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, `issuer ${JSON.stringify(issuer)} is not a valid URL`);
  }
  const isLoopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !isLoopback) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'issuer must be an https URL (localhost exempt)');
  }
  if (isNonEmptyString(url.search) || isNonEmptyString(url.hash)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'issuer must not contain a query or fragment');
  }
}
