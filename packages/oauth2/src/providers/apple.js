/**
 * Apple ("Sign in with Apple") — OpenID Connect provider. Apple has no
 * userinfo endpoint: the user is resolved entirely from the verified
 * id_token. Requesting `name` / `email` forces `response_mode=form_post`,
 * so Apple POSTs the callback — pass the parsed form body to `callback()`
 * as the query.
 *
 * Apple's `clientSecret` is a short-lived ES256 JWT you generate from
 * your Apple private key (not a static secret); pass it as `clientSecret`.
 *
 * @example
 * import { apple } from '@exortek/oauth2/providers/apple';
 * apple({ clientId, clientSecret: appleClientSecretJwt });
 */
import { defineProvider } from './_base.js';

export const apple = defineProvider({
  id: 'apple',
  kind: 'oidc',
  authorizationEndpoint: 'https://appleid.apple.com/auth/authorize',
  tokenEndpoint: 'https://appleid.apple.com/auth/token',
  jwksUri: 'https://appleid.apple.com/auth/keys',
  issuer: 'https://appleid.apple.com',
  idTokenAlgs: ['RS256'],
  // Apple rejects an explicit `openid` scope; it returns an id_token
  // regardless. Requesting name/email requires the form_post response.
  autoOpenidScope: false,
  defaultScopes: ['name', 'email'],
  authorizationParams: { response_mode: 'form_post' },
  mapUser: (_raw, claims = {}) => ({
    sub: claims.sub,
    email: claims.email,
    emailVerified: claims.email_verified === true || claims.email_verified === 'true',
  }),
});
