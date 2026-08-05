/**
 * Google — OpenID Connect provider.
 *
 * @example
 * import { google } from '@exortek/oauth2/providers/google';
 * google({ clientId, clientSecret, scope: ['email', 'profile'] });
 */
import { defineProvider } from './_base.js';

export const google = defineProvider({
  id: 'google',
  kind: 'oidc',
  authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenEndpoint: 'https://oauth2.googleapis.com/token',
  userinfoEndpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
  revocationEndpoint: 'https://oauth2.googleapis.com/revoke',
  jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
  issuer: 'https://accounts.google.com',
  idTokenAlgs: ['RS256'],
  defaultScopes: ['openid', 'email', 'profile'],
  // `access_type=offline` asks for a refresh token; `prompt=consent`
  // makes Google re-issue one on repeat consent.
  authorizationParams: { access_type: 'offline', prompt: 'consent' },
  mapUser: raw => ({
    sub: raw.sub,
    email: raw.email,
    emailVerified: raw.email_verified,
    name: raw.name,
    picture: raw.picture,
  }),
});
