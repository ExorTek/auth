/**
 * Facebook (Meta) — OAuth 2.0 provider. Identity comes from the Graph
 * `me` endpoint. The Graph API version is versioned in the URL and each
 * version is supported by Meta for roughly two years, so it is a
 * per-app option: pass `version` (e.g. `'v26.0'`) to pin the one your
 * app is configured for. The default tracks a current, well-supported
 * version. Facebook does not report email verification, so
 * `emailVerified` is left unset.
 *
 * @example
 * import { facebook } from '@exortek/oauth2/providers/facebook';
 * facebook({ clientId, clientSecret });                  // default version
 * facebook({ clientId, clientSecret, version: 'v26.0' }); // pin a version
 */
import { defineProvider } from './_base.js';

// A recent, well-supported Graph version. Overridable per app so callers
// can match whatever their Meta app is pinned to without waiting on us.
const DEFAULT_VERSION = 'v23.0';

/**
 * @param {{ clientId: string, clientSecret?: string, version?: string, scope?: string[], redirectUri?: string, id?: string }} options
 */
export function facebook(options = {}) {
  const { version = DEFAULT_VERSION, ...appOptions } = options;
  return defineProvider({
    id: 'facebook',
    kind: 'oauth2',
    authorizationEndpoint: `https://www.facebook.com/${version}/dialog/oauth`,
    tokenEndpoint: `https://graph.facebook.com/${version}/oauth/access_token`,
    userinfoEndpoint: `https://graph.facebook.com/${version}/me?fields=id,name,email,picture`,
    defaultScopes: ['email', 'public_profile'],
    mapUser: raw => ({
      sub: String(raw.id),
      email: raw.email,
      name: raw.name,
      picture: raw.picture?.data?.url,
    }),
  })(appOptions);
}
