/**
 * Okta — OpenID Connect provider. Okta endpoints are per-org, so pass
 * your authorization-server `issuer` (e.g.
 * `https://your-org.okta.com/oauth2/default`); the endpoints are
 * resolved from its discovery document.
 *
 * @example
 * import { okta } from '@exortek/oauth2/providers/okta';
 * okta({ clientId, clientSecret, issuer: 'https://your-org.okta.com/oauth2/default' });
 */
import { isNonEmptyString } from '@exortek/shared/predicates';

import { ErrorCode, OAuth2Error } from '../internal/errors.js';
import { defineProvider } from './_base.js';

/**
 * @param {{ clientId: string, clientSecret?: string, issuer: string, scope?: string[], redirectUri?: string, id?: string }} options
 */
export function okta(options = {}) {
  const { issuer, ...appOptions } = options;
  if (!isNonEmptyString(issuer)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'okta requires an issuer (your Okta authorization-server URL)');
  }
  return defineProvider({
    id: 'okta',
    kind: 'oidc',
    discover: true,
    issuer,
    idTokenAlgs: ['RS256'],
    defaultScopes: ['openid', 'email', 'profile'],
    mapUser: raw => ({
      sub: raw.sub,
      email: raw.email,
      emailVerified: raw.email_verified,
      name: raw.name,
      picture: raw.picture,
    }),
  })(appOptions);
}
