/**
 * OpenID Connect **RP-Initiated Logout 1.0** helpers.
 *
 * The relying party sends the end user to the OP's `end_session_endpoint`
 * with an `id_token_hint`; the OP ends its session and (after validating the
 * `post_logout_redirect_uri` against the ones registered for the client)
 * redirects back. These are the pure builders/validators shared by the
 * client's `endSessionUrl` and the provider's `endSessionHandler`.
 */
import { decode } from '@exortek/jwt';
import { isArray, isNonEmptyString } from '@exortek/shared/predicates';

/**
 * Build the RP-Initiated Logout URL for the OP's end-session endpoint.
 *
 * @param {string} endpoint  the OP's `end_session_endpoint`
 * @param {{ idTokenHint: string, postLogoutRedirectUri?: string, state?: string, clientId?: string, logoutHint?: string, uiLocales?: string }} params
 * @returns {string}
 */
export function buildEndSessionUrl(endpoint, params) {
  const url = new URL(endpoint);
  const q = url.searchParams;
  q.set('id_token_hint', params.idTokenHint);
  if (isNonEmptyString(params.postLogoutRedirectUri)) {
    q.set('post_logout_redirect_uri', params.postLogoutRedirectUri);
  }
  if (isNonEmptyString(params.state)) {
    q.set('state', params.state);
  }
  if (isNonEmptyString(params.clientId)) {
    q.set('client_id', params.clientId);
  }
  if (isNonEmptyString(params.logoutHint)) {
    q.set('logout_hint', params.logoutHint);
  }
  if (isNonEmptyString(params.uiLocales)) {
    q.set('ui_locales', params.uiLocales);
  }
  return url.toString();
}

/**
 * Read the (unverified) `sub` / `aud` from an `id_token_hint`. A logout hint
 * is frequently expired, so the OP validates issuer/audience rather than the
 * full signature+exp; the return lets the handler match the session to clear.
 *
 * @param {string} idTokenHint
 * @param {string} issuer  the OP's own issuer — the hint's `iss` must match
 * @returns {{ sub?: string, aud?: string | string[] } | null}  null when the hint is unusable / not ours
 */
export function readIdTokenHint(idTokenHint, issuer) {
  if (!isNonEmptyString(idTokenHint)) {
    return null;
  }
  let payload;
  try {
    payload = decode(idTokenHint).payload;
  } catch {
    return null;
  }
  if (payload.iss !== issuer) {
    return null;
  }
  return {
    sub: /** @type {string|undefined} */ (payload.sub),
    aud: /** @type {string|string[]|undefined} */ (payload.aud),
  };
}

/**
 * Exact-match a `post_logout_redirect_uri` against the URIs registered for a
 * client (OIDC RP-Initiated Logout §2 — the OP MUST verify it). Exact string
 * comparison, the same rule redirect_uri validation uses.
 *
 * @param {string | undefined} uri
 * @param {string[]} registered
 * @returns {boolean}
 */
export function isRegisteredPostLogoutUri(uri, registered) {
  return isNonEmptyString(uri) && isArray(registered) && registered.includes(uri);
}
