/**
 * GitLab — OpenID Connect provider (gitlab.com). For a self-managed GitLab
 * instance, build one with `defineProvider({ issuer:
 * 'https://gitlab.example.com', discover: true, … })` — the endpoints are
 * the same shape under your host.
 *
 * @example
 * import { gitlab } from '@exortek/oauth2/providers/gitlab';
 * gitlab({ clientId, clientSecret });
 */
import { defineProvider } from './_base.js';

export const gitlab = defineProvider({
  id: 'gitlab',
  kind: 'oidc',
  authorizationEndpoint: 'https://gitlab.com/oauth/authorize',
  tokenEndpoint: 'https://gitlab.com/oauth/token',
  userinfoEndpoint: 'https://gitlab.com/oauth/userinfo',
  revocationEndpoint: 'https://gitlab.com/oauth/revoke',
  jwksUri: 'https://gitlab.com/oauth/discovery/keys',
  issuer: 'https://gitlab.com',
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
