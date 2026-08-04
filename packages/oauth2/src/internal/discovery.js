/**
 * OpenID Connect / OAuth 2.0 Authorization Server discovery
 * (OIDC Discovery, RFC 8414). Point a provider at its `issuer` and pull
 * `authorization_endpoint` / `token_endpoint` / `jwks_uri` /
 * `userinfo_endpoint` from `/.well-known/openid-configuration` instead
 * of hardcoding them — makes a custom `defineProvider` for Keycloak,
 * Zitadel, Auth0, or Okta a one-liner.
 *
 * Results are cached per issuer for the process lifetime with a TTL;
 * discovery documents are stable and refetched rarely.
 */
import { isNonEmptyString } from '@exortek/shared/predicates';
import { parseDuration } from '@exortek/shared/duration';

import { ErrorCode, OAuth2Error } from './errors.js';
import { getJson } from './http.js';

const WELL_KNOWN = '/.well-known/openid-configuration';
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24h

/** @type {Map<string, { at: number, doc: DiscoveryDocument }>} */
const cache = new Map();

/**
 * @typedef {Object} DiscoveryDocument
 * @property {string} issuer
 * @property {string} authorizationEndpoint
 * @property {string} tokenEndpoint
 * @property {string} [userinfoEndpoint]
 * @property {string} [jwksUri]
 * @property {string} [revocationEndpoint]
 * @property {Record<string, unknown>} raw
 */

/**
 * Resolve the discovery document for `issuer`.
 *
 * @param {string} issuer
 * @param {{ ttl?: string|number, timeout?: number }} [options]
 * @returns {Promise<DiscoveryDocument>}
 */
export async function discover(issuer, options = {}) {
  if (!isNonEmptyString(issuer)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'issuer must be a non-empty string');
  }

  const ttl = options.ttl !== undefined ? parseDuration(options.ttl) : DEFAULT_TTL_MS;
  const hit = cache.get(issuer);
  if (hit && Date.now() - hit.at < ttl) {
    return hit.doc;
  }

  // The issuer identifier has no trailing slash (OIDC Discovery §4); the
  // well-known path is appended to it directly.
  const url = `${issuer.replace(/\/$/, '')}${WELL_KNOWN}`;
  const raw = await getJson(url, {}, { timeout: options.timeout, errorCode: ErrorCode.DISCOVERY_FAILED });

  // RFC 9207 / OIDC: the document's own `issuer` must match the one we
  // asked for, or an attacker could redirect discovery to a rogue AS.
  if (raw.issuer !== issuer) {
    throw new OAuth2Error(
      ErrorCode.DISCOVERY_FAILED,
      `discovery document issuer ${JSON.stringify(raw.issuer)} does not match requested issuer ${JSON.stringify(issuer)}`,
    );
  }
  if (!isNonEmptyString(raw.authorization_endpoint) || !isNonEmptyString(raw.token_endpoint)) {
    throw new OAuth2Error(ErrorCode.DISCOVERY_FAILED, `discovery document at ${url} is missing required endpoints`);
  }

  /** @type {DiscoveryDocument} */
  const doc = {
    issuer,
    authorizationEndpoint: raw.authorization_endpoint,
    tokenEndpoint: raw.token_endpoint,
    userinfoEndpoint: isNonEmptyString(raw.userinfo_endpoint) ? raw.userinfo_endpoint : undefined,
    jwksUri: isNonEmptyString(raw.jwks_uri) ? raw.jwks_uri : undefined,
    revocationEndpoint: isNonEmptyString(raw.revocation_endpoint) ? raw.revocation_endpoint : undefined,
    raw,
  };

  cache.set(issuer, { at: Date.now(), doc });
  return doc;
}

/** Clear the discovery cache — test hook. */
export function _clearDiscoveryCache() {
  cache.clear();
}
