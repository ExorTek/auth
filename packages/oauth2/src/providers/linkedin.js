/**
 * LinkedIn — OpenID Connect provider ("Sign In with LinkedIn using
 * OpenID Connect"). The issuer is `https://www.linkedin.com/oauth`; the
 * userinfo endpoint lives on the API host.
 *
 * @example
 * import { linkedin } from '@exortek/oauth2/providers/linkedin';
 * linkedin({ clientId, clientSecret });
 */
import { defineProvider } from './_base.js';

export const linkedin = defineProvider({
  id: 'linkedin',
  kind: 'oidc',
  authorizationEndpoint: 'https://www.linkedin.com/oauth/v2/authorization',
  tokenEndpoint: 'https://www.linkedin.com/oauth/v2/accessToken',
  userinfoEndpoint: 'https://api.linkedin.com/v2/userinfo',
  jwksUri: 'https://www.linkedin.com/oauth/openid/jwks',
  issuer: 'https://www.linkedin.com/oauth',
  idTokenAlgs: ['RS256'],
  defaultScopes: ['openid', 'profile', 'email'],
  mapUser: raw => ({
    sub: raw.sub,
    email: raw.email,
    emailVerified: raw.email_verified,
    name: raw.name,
    picture: raw.picture,
  }),
});
