/**
 * GitHub — OAuth 2.0 provider. GitHub has no id_token and no OIDC
 * userinfo; identity comes from `GET /user`, and the verified primary
 * email from a second call to `GET /user/emails` (the email may be
 * private on the profile). Every API call needs a `User-Agent`, and the
 * token endpoint only returns JSON when asked with `Accept`.
 *
 * @example
 * import { github } from '@exortek/oauth2/providers/github';
 * github({ clientId, clientSecret });
 */
import { defineProvider } from './_base.js';

export const github = defineProvider({
  id: 'github',
  kind: 'oauth2',
  authorizationEndpoint: 'https://github.com/login/oauth/authorize',
  tokenEndpoint: 'https://github.com/login/oauth/access_token',
  userinfoEndpoint: 'https://api.github.com/user',
  emailEndpoint: 'https://api.github.com/user/emails',
  defaultScopes: ['read:user', 'user:email'],
  tokenHeaders: { 'user-agent': 'exortek-oauth2', accept: 'application/json' },
  userinfoHeaders: { 'user-agent': 'exortek-oauth2', accept: 'application/vnd.github+json' },
  mapUser: raw => {
    const emails = Array.isArray(raw.emails) ? raw.emails : [];
    const primary = emails.find(e => e && e.primary) ?? emails.find(e => e && e.verified) ?? emails[0];
    return {
      sub: String(raw.id),
      email: primary?.email ?? (typeof raw.email === 'string' ? raw.email : undefined),
      emailVerified: primary ? primary.verified === true : undefined,
      name: raw.name ?? raw.login,
      picture: raw.avatar_url,
    };
  },
});
