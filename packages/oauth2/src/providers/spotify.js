/**
 * Spotify — OAuth 2.0 provider. Identity comes from `GET /v1/me`.
 * Spotify does not report email verification.
 *
 * @example
 * import { spotify } from '@exortek/oauth2/providers/spotify';
 * spotify({ clientId, clientSecret });
 */
import { defineProvider } from './_base.js';
import { isArray } from '@exortek/shared/predicates';

export const spotify = defineProvider({
  id: 'spotify',
  kind: 'oauth2',
  authorizationEndpoint: 'https://accounts.spotify.com/authorize',
  tokenEndpoint: 'https://accounts.spotify.com/api/token',
  userinfoEndpoint: 'https://api.spotify.com/v1/me',
  defaultScopes: ['user-read-email', 'user-read-private'],
  mapUser: raw => ({
    sub: raw.id,
    email: raw.email,
    name: raw.display_name,
    picture: isArray(raw.images) && raw.images[0] ? raw.images[0].url : undefined,
  }),
});
