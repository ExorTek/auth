/**
 * Microsoft Entra ID (Azure AD) shared builder — backs both the
 * `microsoft` and `azure` presets, which target the same v2 endpoints.
 *
 * A concrete `tenant` (GUID or verified domain) pins the issuer exactly.
 * For the multi-tenant keywords (`common` / `organizations` /
 * `consumers`) the id_token issuer is directory-specific, so the issuer
 * is validated with a pattern that still requires a genuine Microsoft
 * login issuer — never left unchecked.
 */
import { defineProvider } from './_base.js';

const MULTI_TENANT = new Set(['common', 'organizations', 'consumers']);
const TENANT_ISSUER = /^https:\/\/login\.microsoftonline\.com\/[0-9a-f-]{36}\/v2\.0$/i;

// The tenant-derived endpoints/issuer depend only on the tenant, not on
// the preset id or the app credentials — memoise them so the `microsoft`
// and `azure` presets (and repeated builds) reuse one computed bundle.
/** @type {Map<string, { base: string, issuer: string | ((claimed: string) => boolean) }>} */
const tenantCache = new Map();

/**
 * @param {string} tenant
 * @returns {{ base: string, issuer: string | ((claimed: string) => boolean) }}
 */
function tenantConfig(tenant) {
  let cfg = tenantCache.get(tenant);
  if (!cfg) {
    const base = `https://login.microsoftonline.com/${encodeURIComponent(tenant)}`;
    const issuer = MULTI_TENANT.has(tenant) ? claimed => TENANT_ISSUER.test(claimed) : `${base}/v2.0`;
    cfg = { base, issuer };
    tenantCache.set(tenant, cfg);
  }
  return cfg;
}

/**
 * @param {string} id
 * @param {{ tenant?: string, clientId: string, clientSecret?: string, scope?: string[], redirectUri?: string, id?: string }} options
 */
export function createEntraProvider(id, options = {}) {
  const { tenant = 'common', ...appOptions } = options;
  const { base, issuer } = tenantConfig(tenant);

  return defineProvider({
    id,
    kind: 'oidc',
    authorizationEndpoint: `${base}/oauth2/v2.0/authorize`,
    tokenEndpoint: `${base}/oauth2/v2.0/token`,
    jwksUri: `${base}/discovery/v2.0/keys`,
    userinfoEndpoint: 'https://graph.microsoft.com/oidc/userinfo',
    issuer,
    idTokenAlgs: ['RS256'],
    defaultScopes: ['openid', 'email', 'profile'],
    mapUser: raw => ({
      sub: raw.sub,
      email: raw.email,
      emailVerified: raw.email_verified,
      name: raw.name,
      picture: raw.picture,
    }),
  })(appOptions);
}
