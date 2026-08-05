/**
 * Salesforce — OpenID Connect (production `login.salesforce.com`). For a
 * sandbox point `defineProvider` at `test.salesforce.com`, and for a My
 * Domain org use `defineProvider({ issuer:
 * 'https://<mydomain>.my.salesforce.com', discover: true, … })`.
 *
 * @example
 * import { salesforce } from '@exortek/oauth2/providers/salesforce';
 * salesforce({ clientId, clientSecret });
 */
import { defineProvider } from './_base.js';

export const salesforce = defineProvider({
  id: 'salesforce',
  kind: 'oidc',
  authorizationEndpoint: 'https://login.salesforce.com/services/oauth2/authorize',
  tokenEndpoint: 'https://login.salesforce.com/services/oauth2/token',
  userinfoEndpoint: 'https://login.salesforce.com/services/oauth2/userinfo',
  revocationEndpoint: 'https://login.salesforce.com/services/oauth2/revoke',
  jwksUri: 'https://login.salesforce.com/id/keys',
  issuer: 'https://login.salesforce.com',
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
