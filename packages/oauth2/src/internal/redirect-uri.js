/**
 * Derive the `redirect_uri` from the adapter's `baseUrl` + `callback`
 * template (PLAN.md — "redirectUri is derived").
 *
 * The resolved value is the exact string sent on the authorization
 * request *and* replayed at the token exchange. It is never matched by
 * prefix — an open-redirect (threat #4) is only prevented if both legs
 * carry the identical string, so we compute it once here and reuse it.
 *
 * Transport is `https` only (threat #14, cleartext transport), with
 * loopback (`localhost` / `127.0.0.1` / `[::1]`) exempt so local
 * development works without a certificate.
 */
import { isNonEmptyString } from '@exortek/shared/predicates';

import { ErrorCode, OAuth2Error } from './errors.js';

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/**
 * @param {string} baseUrl           e.g. `https://app.com`
 * @param {string} callbackTemplate  e.g. `/auth/{provider}/callback`
 * @param {string} providerId        substituted for `{provider}`
 * @param {string} [override]        explicit redirect_uri (odd callback paths)
 * @returns {string} the absolute, exact-match redirect URI
 */
export function resolveRedirectUri(baseUrl, callbackTemplate, providerId, override) {
  if (isNonEmptyString(override)) {
    return assertSecure(new URL(override)).toString();
  }

  if (!isNonEmptyString(baseUrl)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'baseUrl must be a non-empty string');
  }
  if (!isNonEmptyString(callbackTemplate)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'callback must be a non-empty string');
  }

  const path = callbackTemplate.replace('{provider}', encodeURIComponent(providerId));

  /** @type {URL} */
  let url;
  try {
    // `URL(path, base)` resolves the callback path against the base
    // origin; a fully-qualified `callback` overrides the base entirely.
    url = new URL(path, baseUrl);
  } catch (err) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, `cannot derive redirect_uri from baseUrl + callback`, {
      cause: err,
    });
  }

  return assertSecure(url).toString();
}

/**
 * @param {URL} url
 * @returns {URL}
 */
function assertSecure(url) {
  const isLoopback = LOOPBACK_HOSTS.has(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback)) {
    throw new OAuth2Error(
      ErrorCode.INVALID_ARGUMENT,
      `redirect_uri must use https (got ${url.protocol}//${url.host}); http is only allowed for loopback`,
    );
  }
  return url;
}
