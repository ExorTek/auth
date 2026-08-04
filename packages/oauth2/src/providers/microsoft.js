/**
 * Microsoft (Entra ID / Azure AD) — OpenID Connect provider.
 *
 * Pass a `tenant` (GUID or verified domain) to pin a single directory,
 * or leave the default `common` for the multi-tenant endpoint.
 *
 * @example
 * import { microsoft } from '@exortek/oauth2/providers/microsoft';
 * microsoft({ clientId, clientSecret, tenant: 'common' });
 */
import { createEntraProvider } from './_entra.js';

/**
 * @param {{ clientId: string, clientSecret?: string, tenant?: string, scope?: string[], redirectUri?: string, id?: string }} options
 */
export function microsoft(options) {
  return createEntraProvider('microsoft', options);
}
