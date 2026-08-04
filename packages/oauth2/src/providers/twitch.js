/**
 * Twitch — OpenID Connect provider. Twitch only returns the extra
 * profile claims when they are named in the `claims` request parameter,
 * so the preset asks for them on the userinfo endpoint; email also needs
 * the `user:read:email` scope.
 *
 * @example
 * import { twitch } from '@exortek/oauth2/providers/twitch';
 * twitch({ clientId, clientSecret });
 */
import { defineProvider } from './_base.js';

const CLAIMS = JSON.stringify({
  userinfo: { email: null, email_verified: null, preferred_username: null, picture: null },
});

export const twitch = defineProvider({
  id: 'twitch',
  kind: 'oidc',
  authorizationEndpoint: 'https://id.twitch.tv/oauth2/authorize',
  tokenEndpoint: 'https://id.twitch.tv/oauth2/token',
  userinfoEndpoint: 'https://id.twitch.tv/oauth2/userinfo',
  jwksUri: 'https://id.twitch.tv/oauth2/keys',
  issuer: 'https://id.twitch.tv/oauth2',
  idTokenAlgs: ['RS256'],
  defaultScopes: ['openid', 'user:read:email'],
  authorizationParams: { claims: CLAIMS },
  mapUser: raw => ({
    sub: raw.sub,
    email: raw.email,
    emailVerified: raw.email_verified,
    name: raw.preferred_username,
    picture: raw.picture,
  }),
});
