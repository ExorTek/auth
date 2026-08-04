/**
 * X (Twitter) — OAuth 2.0 provider. PKCE (S256) is mandatory and the
 * confidential client authenticates with HTTP Basic at the token
 * endpoint. Identity comes from `GET /2/users/me`; X does not expose
 * email through this flow, so `email` is left unset. `offline.access`
 * is requested so a refresh token is issued.
 *
 * @example
 * import { twitter } from '@exortek/oauth2/providers/twitter';
 * twitter({ clientId, clientSecret });
 */
import { defineProvider } from './_base.js';

export const twitter = defineProvider({
  id: 'twitter',
  kind: 'oauth2',
  authorizationEndpoint: 'https://twitter.com/i/oauth2/authorize',
  tokenEndpoint: 'https://api.x.com/2/oauth2/token',
  userinfoEndpoint: 'https://api.x.com/2/users/me?user.fields=profile_image_url,name,username',
  clientAuth: 'basic',
  defaultScopes: ['users.read', 'tweet.read', 'offline.access'],
  mapUser: raw => {
    const data = raw?.data ?? {};
    return {
      sub: String(data.id),
      name: data.name,
      picture: data.profile_image_url,
    };
  },
});
