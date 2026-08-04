/**
 * Azure AD — alias of the Microsoft Entra ID provider under the `azure`
 * key, for callers who prefer that name. Same v2 endpoints and tenant
 * handling as `microsoft`.
 *
 * @example
 * import { azure } from '@exortek/oauth2/providers/azure';
 * azure({ clientId, clientSecret, tenant: '<tenant-guid>' });
 */
import { createEntraProvider } from './_entra.js';

/**
 * @param {{ clientId: string, clientSecret?: string, tenant?: string, scope?: string[], redirectUri?: string, id?: string }} options
 */
export function azure(options) {
  return createEntraProvider('azure', options);
}
