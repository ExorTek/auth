/**
 * Shared route table for the provider's framework adapters. The endpoints a
 * provider actually serves are exactly the ones its discovery document
 * advertises, so the table is derived from `provider.metadata()` — mount only
 * what is announced, at the path the metadata names.
 */
import { isNonEmptyString } from '@exortek/shared/predicates';

/**
 * @param {ReturnType<import('./index.js').createProvider>} provider
 * @returns {Record<string, { method: string, path: string, handler: Function }>}
 */
export function providerRoutes(provider) {
  const meta = provider.metadata();
  /** @type {Record<string, { method: string, path: string, handler: Function }>} */
  const routes = {
    discovery: { method: 'GET', path: '/.well-known/openid-configuration', handler: provider.discoveryHandler() },
    jwks: { method: 'GET', path: pathOf(meta.jwks_uri), handler: provider.jwksHandler() },
  };
  if (isNonEmptyString(meta.userinfo_endpoint)) {
    routes.userinfo = { method: 'GET', path: pathOf(meta.userinfo_endpoint), handler: provider.userinfoHandler() };
  }
  if (isNonEmptyString(meta.end_session_endpoint)) {
    routes.endSession = {
      method: 'GET',
      path: pathOf(meta.end_session_endpoint),
      handler: provider.endSessionHandler(),
    };
  }
  if (isNonEmptyString(meta.check_session_iframe)) {
    routes.checkSession = {
      method: 'GET',
      path: pathOf(meta.check_session_iframe),
      handler: provider.checkSessionHandler(),
    };
  }
  return routes;
}

/**
 * The path portion of an advertised endpoint URL (absolute or already a path).
 *
 * @param {unknown} url
 * @returns {string}
 */
export function pathOf(url) {
  if (!isNonEmptyString(url)) {
    return '/';
  }
  try {
    return new URL(url).pathname;
  } catch {
    return url.startsWith('/') ? url : `/${url}`;
  }
}
