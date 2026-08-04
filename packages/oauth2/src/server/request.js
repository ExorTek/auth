/**
 * Normalized server request — the framework-agnostic descriptor every
 * handler consumes. `@exortek/session` and `@exortek/apikey` keep their
 * core logic off any one framework the same way; the thin `./server/
 * fastify` and `./server/express` adapters translate a native
 * request/reply into and out of these shapes.
 *
 * A caller (or an adapter) hands in `{ method, url, headers, query?,
 * body? }`. This module lower-cases the headers, resolves the query from
 * either the supplied object or the URL, parses a form / JSON body into
 * a flat params object, and exposes the raw client-authentication
 * material (Basic header, body credentials, `client_assertion`, DPoP
 * proof, client TLS cert) for `security/client-auth.js` to resolve.
 */
import { isArray, isNonEmptyString, isNullish, isObject, isString } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from './errors.js';

/**
 * @typedef {Object} RawRequest
 * @property {string} [method]
 * @property {string} [url]                                   full URL or path (`?query` parsed when `query` is absent)
 * @property {Record<string, string | string[]>} [headers]
 * @property {Record<string, unknown>} [query]               pre-parsed query, else derived from `url`
 * @property {string | Record<string, unknown>} [body]       raw string or a framework-parsed object
 * @property {import('node:tls').PeerCertificate | Record<string, unknown>} [clientCertificate]  mTLS client cert (RFC 8705)
 *
 * @typedef {Object} ServerRequest
 * @property {string} method
 * @property {Record<string, string>} headers                lower-cased names
 * @property {Record<string, string>} query
 * @property {Record<string, string>} form                   parsed POST body params
 * @property {(name: string) => string | undefined} header
 * @property {(name: string) => string | undefined} param    query ∪ form (form wins)
 * @property {object | undefined} clientCertificate
 */

/**
 * Build a {@link ServerRequest} from a raw descriptor.
 *
 * @param {RawRequest} raw
 * @returns {ServerRequest}
 */
export function normalizeRequest(raw) {
  if (!isObject(raw)) {
    throw new ServerError(ProtocolError.INVALID_REQUEST, 'request descriptor must be an object');
  }

  const method = isNonEmptyString(raw.method) ? raw.method.toUpperCase() : 'GET';
  const headers = lowerCaseHeaders(raw.headers);
  const query = raw.query !== undefined ? flattenParams(raw.query) : queryFromUrl(raw.url);
  const form = parseBody(raw.body, headers['content-type']);

  return {
    method,
    headers,
    query,
    form,
    clientCertificate: isObject(raw.clientCertificate) ? raw.clientCertificate : undefined,
    header(name) {
      return headers[String(name).toLowerCase()];
    },
    param(name) {
      return Object.hasOwn(form, name) ? form[name] : query[name];
    },
  };
}

// HEADERS

/**
 * @param {Record<string, string | string[]> | undefined} headers
 * @returns {Record<string, string>}
 */
function lowerCaseHeaders(headers) {
  /** @type {Record<string, string>} */
  const out = {};
  if (!isObject(headers)) {
    return out;
  }
  for (const [name, value] of Object.entries(headers)) {
    // A repeated header arrives as an array; join per RFC 9110 §5.3.
    out[name.toLowerCase()] = isArray(value) ? value.join(', ') : String(value);
  }
  return out;
}

// QUERY / BODY

/**
 * @param {string | undefined} url
 * @returns {Record<string, string>}
 */
function queryFromUrl(url) {
  if (!isNonEmptyString(url)) {
    return {};
  }
  const q = url.indexOf('?');
  if (q === -1) {
    return {};
  }
  return searchParamsToObject(new URLSearchParams(url.slice(q + 1)));
}

/**
 * Parse a request body into flat string params. A framework may hand us
 * an already-parsed object; otherwise we decode `application/x-www-form-
 * urlencoded` (the OAuth default for the token endpoint) or JSON.
 *
 * @param {string | Record<string, unknown> | undefined} body
 * @param {string | undefined} contentType
 * @returns {Record<string, string>}
 */
function parseBody(body, contentType) {
  if (isNullish(body)) {
    return {};
  }
  if (isObject(body)) {
    return flattenParams(body);
  }
  if (!isString(body) || body.length === 0) {
    return {};
  }
  const type = isNonEmptyString(contentType) ? contentType.split(';', 1)[0].trim().toLowerCase() : '';
  if (type === 'application/json') {
    try {
      const parsed = JSON.parse(body);
      return isObject(parsed) ? flattenParams(parsed) : {};
    } catch {
      throw new ServerError(ProtocolError.INVALID_REQUEST, 'request body is not valid JSON');
    }
  }
  // Default: form-urlencoded (RFC 6749 §4.1.3 requires it at the token endpoint).
  return searchParamsToObject(new URLSearchParams(body));
}

/**
 * @param {URLSearchParams} params
 * @returns {Record<string, string>}
 */
function searchParamsToObject(params) {
  /** @type {Record<string, string>} */
  const out = {};
  // Last value wins on a repeated key — RFC 6749 §3.1 forbids repeated
  // request parameters, so collapsing rather than arraying is correct.
  for (const [key, value] of params) {
    out[key] = value;
  }
  return out;
}

/**
 * Coerce a params object to flat strings, dropping absent values. Nested
 * structures (e.g. RAR `authorization_details`) are kept verbatim so the
 * relevant handler can validate them; everything else becomes a string.
 *
 * @param {Record<string, unknown>} obj
 * @returns {Record<string, string>}
 */
function flattenParams(obj) {
  /** @type {Record<string, string>} */
  const out = {};
  for (const [key, value] of Object.entries(obj)) {
    if (isNullish(value)) {
      continue;
    }
    out[key] = isString(value) ? value : /** @type {string} */ (/** @type {unknown} */ (value));
  }
  return out;
}

// CLIENT-AUTH MATERIAL

/**
 * @typedef {Object} ClientCredentials
 * @property {string} clientId
 * @property {string} [clientSecret]
 * @property {'client_secret_basic' | 'client_secret_post'} [via]
 *
 * Extract a `client_id` / `client_secret` presented via HTTP Basic
 * (RFC 6749 §2.3.1) or POST body (§2.3.1 alt). Basic wins when both are
 * present, and presenting credentials both ways is itself an error
 * (§2.3.1). Assertion-based auth (`private_key_jwt` / mTLS) is resolved
 * separately from `client_assertion` / the client certificate.
 *
 * @param {ServerRequest} req
 * @returns {ClientCredentials | undefined}
 */
export function readClientCredentials(req) {
  const basic = parseBasicAuthorization(req.header('authorization'));
  const bodyId = req.form.client_id;
  const bodySecret = req.form.client_secret;

  if (basic) {
    if (isNonEmptyString(bodySecret)) {
      throw new ServerError(
        ProtocolError.INVALID_REQUEST,
        'client credentials presented both in the Authorization header and the request body',
      );
    }
    return { clientId: basic.clientId, clientSecret: basic.clientSecret, via: 'client_secret_basic' };
  }
  if (isNonEmptyString(bodyId)) {
    return {
      clientId: bodyId,
      clientSecret: isNonEmptyString(bodySecret) ? bodySecret : undefined,
      via: isNonEmptyString(bodySecret) ? 'client_secret_post' : undefined,
    };
  }
  return undefined;
}

/**
 * Decode a `Basic` Authorization header. Per RFC 6749 §2.3.1 the id and
 * secret are `application/x-www-form-urlencoded` before base64 — a step
 * naive parsers skip, breaking secrets that contain `+`, `/` or `=`.
 *
 * @param {string | undefined} header
 * @returns {{ clientId: string, clientSecret: string } | undefined}
 */
export function parseBasicAuthorization(header) {
  if (!isNonEmptyString(header)) {
    return undefined;
  }
  const [scheme, encoded] = header.split(' ', 2);
  if (scheme.toLowerCase() !== 'basic' || !isNonEmptyString(encoded)) {
    return undefined;
  }
  let decoded;
  try {
    decoded = Buffer.from(encoded, 'base64').toString('utf8');
  } catch {
    return undefined;
  }
  const colon = decoded.indexOf(':');
  if (colon === -1) {
    return undefined;
  }
  return {
    clientId: formUrlDecode(decoded.slice(0, colon)),
    clientSecret: formUrlDecode(decoded.slice(colon + 1)),
  };
}

/** @param {string} value @returns {string} */
function formUrlDecode(value) {
  // `+` is a space in x-www-form-urlencoded; decodeURIComponent alone
  // would leave it. Match the encoder RFC 6749 §2.3.1 mandates.
  return decodeURIComponent(value.replace(/\+/g, ' '));
}
