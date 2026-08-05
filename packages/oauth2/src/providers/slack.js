/**
 * Slack — "Sign in with Slack" (OpenID Connect). Note the non-standard
 * endpoint paths (`/api/openid.connect.*`); the id_token and userInfo carry
 * the standard OIDC claims plus Slack team / user ids.
 *
 * @example
 * import { slack } from '@exortek/oauth2/providers/slack';
 * slack({ clientId, clientSecret });
 */
import { defineProvider } from './_base.js';

export const slack = defineProvider({
  id: 'slack',
  kind: 'oidc',
  authorizationEndpoint: 'https://slack.com/openid/connect/authorize',
  tokenEndpoint: 'https://slack.com/api/openid.connect.token',
  userinfoEndpoint: 'https://slack.com/api/openid.connect.userInfo',
  jwksUri: 'https://slack.com/openid/connect/keys',
  issuer: 'https://slack.com',
  idTokenAlgs: ['RS256'],
  defaultScopes: ['openid', 'email', 'profile'],
  mapUser: raw => ({
    sub: raw.sub,
    email: raw.email,
    emailVerified: raw.email_verified,
    name: raw.name,
    picture: raw.picture,
  }),
});
