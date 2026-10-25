/**
 * Internal HTTP client for the RP flow — token exchange, userinfo,
 * discovery, revocation. Node 22's global `fetch` (undici) only; no
 * third-party HTTP dependency.
 *
 * Transport guards come from the shared `fetchCapped` (also used by
 * `@exortek/jwks`):
 *   - one timeout over the request AND the body read,
 *   - `redirect: 'manual'` — a redirect from a token/userinfo endpoint is
 *     never legitimate and is an SSRF lever, so we refuse it,
 *   - `content-length` pre-check + a streaming cap at `maxResponseSize`,
 *   - non-2xx → a typed {@link OAuth2Error} with a caller-chosen code,
 *   - `JSON.parse` guarded so a malformed body is a typed error, not a
 *     raw `SyntaxError`.
 */
import { fetchCapped } from '@exortek/shared/fetch-capped';
import { isArray, isObject, isString } from '@exortek/shared/predicates';
import { ErrorCode, OAuth2Error } from './errors.js';

const DEFAULT_TIMEOUT_MS = 8_000;
const DEFAULT_MAX_RESPONSE_SIZE = 1_048_576; // 1 MB

/**
 * @typedef {Object} HttpOptions
 * @property {number} [timeout]          request timeout in ms (default 8000)
 * @property {number} [maxResponseSize]  max response bytes accepted (default 1 MB)
 * @property {AbortSignal} [signal]      caller-provided signal, combined with the timeout
 * @property {Record<string, string>} [headers]  extra request headers
 * @property {string} [errorCode]        {@link ErrorCode} used for a non-2xx response
 */

/**
 * Run a `fetch` with the shared timeout / SSRF / size guards and return
 * the parsed JSON body. Network and timeout failures surface as
 * `NETWORK_ERROR`; a non-2xx response as `options.errorCode`.
 *
 * @param {string} url
 * @param {RequestInit} init
 * @param {HttpOptions} [options]
 * @returns {Promise<Record<string, unknown>>}
 */
async function requestJson(url, init, options = {}) {
  const {
    timeout = DEFAULT_TIMEOUT_MS,
    maxResponseSize = DEFAULT_MAX_RESPONSE_SIZE,
    signal: externalSignal,
    errorCode = ErrorCode.NETWORK_ERROR,
  } = options;

  const { response: res, text } = await fetchCapped(url, init, {
    timeoutMs: timeout,
    maxBytes: maxResponseSize,
    signal: externalSignal,
    fail: (reason, message, cause) =>
      reason === 'timeout' || reason === 'network'
        ? new OAuth2Error(ErrorCode.NETWORK_ERROR, message, { cause })
        : new OAuth2Error(errorCode, reason === 'too_large' ? `${message} (maxResponseSize)` : message),
  });

  /** @type {unknown} */
  let body;
  try {
    body = text.length === 0 ? {} : JSON.parse(text);
  } catch {
    throw new OAuth2Error(errorCode, `${url} responded with a non-JSON body`);
  }

  if (!res.ok) {
    // OAuth error responses carry a machine-readable `error` field
    // (RFC 6749 §5.2); surface it in the message so callers can see why.
    const detail = isObject(body) && isString(body.error) ? `: ${body.error}` : '';
    throw new OAuth2Error(errorCode, `${url} responded with ${res.status}${detail}`, {
      details: isObject(body) ? body : undefined,
    });
  }

  // Preserve arrays as well as objects — some endpoints (e.g. GitHub's
  // /user/emails) return a JSON array. Primitives collapse to `{}`.
  return isObject(body) || isArray(body) ? body : {};
}

/**
 * `POST` an `application/x-www-form-urlencoded` body and parse the JSON
 * response — the token, PAR, and revocation endpoints. `params` values
 * are URL-encoded by {@link URLSearchParams}.
 *
 * @param {string} url
 * @param {Record<string, string>} params
 * @param {HttpOptions} [options]
 * @returns {Promise<Record<string, unknown>>}
 */
export function postForm(url, params, options = {}) {
  return requestJson(
    url,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
        ...options.headers,
      },
      body: new URLSearchParams(params).toString(),
    },
    { ...options, errorCode: options.errorCode ?? ErrorCode.TOKEN_EXCHANGE_FAILED },
  );
}

/**
 * `GET` a JSON resource, optionally with a bearer token — the userinfo
 * and discovery endpoints.
 *
 * @param {string} url
 * @param {{ token?: string }} [auth]
 * @param {HttpOptions} [options]
 * @returns {Promise<Record<string, unknown>>}
 */
export function getJson(url, auth = {}, options = {}) {
  const headers = { accept: 'application/json', ...options.headers };
  if (auth.token) {
    headers.authorization = `Bearer ${auth.token}`;
  }
  return requestJson(
    url,
    { method: 'GET', headers },
    { ...options, errorCode: options.errorCode ?? ErrorCode.USERINFO_FAILED },
  );
}
