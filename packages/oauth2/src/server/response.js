/**
 * Normalized server response — the `{ status, headers, body }` descriptor
 * every handler returns. A framework adapter writes it onto the native
 * reply. Helpers here centralize the response conventions the OAuth RFCs
 * mandate: `Cache-Control: no-store` + `Pragma: no-cache` on any response
 * carrying tokens (RFC 6749 §5.1), the `application/json` content type,
 * and the two error shapes — a token/introspection/revocation JSON body
 * vs. an authorization-endpoint redirect that echoes `state` and `iss`.
 */
import { isNonEmptyString, isObject } from '@exortek/shared/predicates';

import { ServerError } from './errors.js';

/**
 * @typedef {Object} ServerResponse
 * @property {number} status
 * @property {Record<string, string>} headers
 * @property {string} body
 */

const NO_STORE = Object.freeze({
  'cache-control': 'no-store',
  pragma: 'no-cache',
});

/**
 * A JSON response with the token-endpoint no-store headers.
 *
 * @param {number} status
 * @param {Record<string, unknown>} payload
 * @param {Record<string, string>} [headers]
 * @returns {ServerResponse}
 */
export function json(status, payload, headers = {}) {
  return {
    status,
    headers: { ...NO_STORE, ...lower(headers), 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  };
}

/**
 * A 302 redirect. `params` are merged into the target's query string
 * (existing query preserved) so the authorization-endpoint success and
 * error redirects share one builder.
 *
 * @param {string} location                       absolute redirect URI
 * @param {Record<string, string | undefined>} [params]
 * @param {Record<string, string>} [headers]
 * @returns {ServerResponse}
 */
export function redirect(location, params = {}, headers = {}) {
  return {
    status: 302,
    headers: { ...NO_STORE, ...lower(headers), location: appendQuery(location, params) },
    body: '',
  };
}

/**
 * Render a {@link ServerError} as a direct JSON error body (RFC 6749
 * §5.2) — the shape used by the token, introspection, and revocation
 * endpoints. `invalid_client` carries a `WWW-Authenticate` challenge.
 *
 * @param {ServerError} err
 * @returns {ServerResponse}
 */
export function jsonError(err) {
  const payload = { error: err.code };
  if (isNonEmptyString(err.message)) {
    payload.error_description = err.message;
  }
  if (isNonEmptyString(err.errorUri)) {
    payload.error_uri = err.errorUri;
  }
  return json(err.status ?? 400, payload, err.headers ?? {});
}

/**
 * Render a {@link ServerError} raised at the authorization endpoint as a
 * redirect back to the client (RFC 6749 §4.1.2.1), echoing `state` and —
 * per RFC 9207 — the issuer identifier. When there is no usable
 * `redirect_uri` (unknown client / mismatched URI) the error must NOT be
 * redirected (open-redirect / phishing lever); the caller passes
 * `redirectUri: undefined` and gets a direct JSON body instead.
 *
 * @param {string | undefined} redirectUri
 * @param {ServerError} err
 * @param {{ issuer?: string }} [context]
 * @returns {ServerResponse}
 */
export function redirectError(redirectUri, err, context = {}) {
  if (!isNonEmptyString(redirectUri)) {
    return jsonError(err);
  }
  return redirect(redirectUri, {
    error: err.code,
    error_description: isNonEmptyString(err.message) ? err.message : undefined,
    error_uri: err.errorUri,
    state: err.state,
    iss: context.issuer,
  });
}

/**
 * Turn any thrown value into a response. A {@link ServerError} renders as
 * its wire shape; anything else is an internal fault masked as
 * `server_error` (never leak an internal message to the client).
 *
 * @param {unknown} err
 * @param {{ redirectUri?: string, issuer?: string }} [context]
 * @returns {ServerResponse}
 */
export function errorResponse(err, context = {}) {
  if (err instanceof ServerError) {
    return err.redirectable ? redirectError(context.redirectUri, err, context) : jsonError(err);
  }
  return json(500, { error: 'server_error' });
}

// INTERNAL

/**
 * @param {string} location
 * @param {Record<string, string | undefined>} params
 * @returns {string}
 */
function appendQuery(location, params) {
  const url = new URL(location);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      url.searchParams.set(key, value);
    }
  }
  return url.href;
}

/** @param {Record<string, string>} headers @returns {Record<string, string>} */
function lower(headers) {
  if (!isObject(headers)) {
    return {};
  }
  /** @type {Record<string, string>} */
  const out = {};
  for (const [name, value] of Object.entries(headers)) {
    out[name.toLowerCase()] = value;
  }
  return out;
}
