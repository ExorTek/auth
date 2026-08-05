/**
 * Bitbucket Cloud — OAuth 2.0. No OIDC; identity comes from `GET /2.0/user`
 * and the primary confirmed email from a second call to
 * `GET /2.0/user/emails` (the email is not on the user object). Scopes are
 * configured on the OAuth consumer in Bitbucket, not sent per request.
 *
 * @example
 * import { bitbucket } from '@exortek/oauth2/providers/bitbucket';
 * bitbucket({ clientId, clientSecret });
 */
import { defineProvider } from './_base.js';
import { isArray, isObject } from '@exortek/shared/predicates';

export const bitbucket = defineProvider({
  id: 'bitbucket',
  kind: 'oauth2',
  authorizationEndpoint: 'https://bitbucket.org/site/oauth2/authorize',
  tokenEndpoint: 'https://bitbucket.org/site/oauth2/access_token',
  userinfoEndpoint: 'https://api.bitbucket.org/2.0/user',
  emailEndpoint: 'https://api.bitbucket.org/2.0/user/emails',
  // Bitbucket ignores a per-request `scope` and uses the consumer's
  // configured scopes; listed here to document what the consumer needs.
  defaultScopes: ['account', 'email'],
  mapUser: raw => {
    const values = isObject(raw.emails) && isArray(raw.emails.values) ? raw.emails.values : [];
    const primary = values.find(e => e && e.is_primary) ?? values.find(e => e && e.is_confirmed) ?? values[0];
    return {
      sub: raw.uuid ?? raw.account_id,
      email: primary?.email,
      emailVerified: primary ? primary.is_confirmed === true : undefined,
      name: raw.display_name ?? raw.nickname,
      picture: raw.links?.avatar?.href,
    };
  },
});
