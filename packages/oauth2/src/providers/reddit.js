/**
 * Reddit — OAuth 2.0. Confidential clients authenticate with HTTP Basic at
 * the token endpoint, every request needs a unique `User-Agent`, and
 * `duration=permanent` is requested so a refresh token is issued. Identity
 * comes from `GET /api/v1/me` on `oauth.reddit.com`; Reddit does not expose
 * an email through this flow, so `email` is left unset.
 *
 * @example
 * import { reddit } from '@exortek/oauth2/providers/reddit';
 * reddit({ clientId, clientSecret });
 */
import { defineProvider } from './_base.js';
import { isString } from '@exortek/shared/predicates';

export const reddit = defineProvider({
  id: 'reddit',
  kind: 'oauth2',
  authorizationEndpoint: 'https://www.reddit.com/api/v1/authorize',
  tokenEndpoint: 'https://www.reddit.com/api/v1/access_token',
  userinfoEndpoint: 'https://oauth.reddit.com/api/v1/me',
  revocationEndpoint: 'https://www.reddit.com/api/v1/revoke_token',
  clientAuth: 'basic',
  defaultScopes: ['identity'],
  // A refresh token is only issued when the authorization is permanent.
  authorizationParams: { duration: 'permanent' },
  // Reddit rejects requests without a unique, descriptive User-Agent.
  tokenHeaders: { 'user-agent': 'exortek-oauth2' },
  userinfoHeaders: { 'user-agent': 'exortek-oauth2' },
  mapUser: raw => ({
    sub: String(raw.id),
    name: raw.name,
    picture: (isString(raw.icon_img) ? raw.icon_img.split('?')[0] : undefined) ?? raw.snoovatar_img,
  }),
});
