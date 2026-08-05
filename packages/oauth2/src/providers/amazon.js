/**
 * Login with Amazon — OAuth 2.0. Identity comes from the profile endpoint;
 * the `profile` scope returns the user's name, email, and user_id. The
 * token endpoint is regional — this preset uses North America
 * (`api.amazon.com`); pass a `tokenEndpoint` override
 * (`api.amazon.co.uk` / `api.amazon.co.jp`) for the EU / Far East regions.
 *
 * @example
 * import { amazon } from '@exortek/oauth2/providers/amazon';
 * amazon({ clientId, clientSecret });
 */
import { defineProvider } from './_base.js';

export const amazon = defineProvider({
  id: 'amazon',
  kind: 'oauth2',
  authorizationEndpoint: 'https://www.amazon.com/ap/oa',
  tokenEndpoint: 'https://api.amazon.com/auth/o2/token',
  userinfoEndpoint: 'https://api.amazon.com/user/profile',
  defaultScopes: ['profile'],
  mapUser: raw => ({
    sub: raw.user_id,
    email: raw.email,
    name: raw.name,
  }),
});
