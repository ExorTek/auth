/**
 * Minimal framework-agnostic request/response shapes for the provider
 * handlers. `@exortek/oauth2`'s server keeps its own equivalents private, so
 * — following the deliberate leaf-package duplication principle — oidc owns a
 * small copy sized to its handful of endpoints (discovery / userinfo / jwks /
 * end-session / check-session). The `./provider/express` and
 * `./provider/fastify` adapters translate native req/res into and out of
 * these.
 *
 * @typedef {object} OidcRequest
 * @property {string} method                       upper-cased HTTP method
 * @property {Record<string, string>} headers      lower-cased header names
 * @property {Record<string, string>} query        parsed query params
 * @property {(name: string) => string | undefined} header
 * @property {(name: string) => string | undefined} param   query lookup
 *
 * @typedef {object} OidcResponse
 * @property {number} status
 * @property {Record<string, string>} headers
 * @property {string} body
 */
import { isObject } from '@exortek/shared/predicates';

/**
 * Build an {@link OidcRequest} from a raw descriptor `{ method, url, headers,
 * query? }`. Query is taken from `query` when present, else parsed from `url`.
 *
 * @param {{ method?: string, url?: string, headers?: Record<string, string | string[]>, query?: Record<string, unknown> }} raw
 * @returns {OidcRequest}
 */
export function normalizeRequest(raw = {}) {
  const method = typeof raw.method === 'string' ? raw.method.toUpperCase() : 'GET';

  /** @type {Record<string, string>} */
  const headers = {};
  if (isObject(raw.headers)) {
    for (const [name, value] of Object.entries(raw.headers)) {
      headers[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
    }
  }

  /** @type {Record<string, string>} */
  const query = {};
  if (isObject(raw.query)) {
    for (const [name, value] of Object.entries(raw.query)) {
      if (value !== undefined && value !== null) {
        query[name] = Array.isArray(value) ? String(value[0]) : String(value);
      }
    }
  } else if (typeof raw.url === 'string') {
    const qIndex = raw.url.indexOf('?');
    if (qIndex !== -1) {
      for (const [name, value] of new URLSearchParams(raw.url.slice(qIndex + 1))) {
        query[name] = value;
      }
    }
  }

  return {
    method,
    headers,
    query,
    header(name) {
      return headers[String(name).toLowerCase()];
    },
    param(name) {
      return query[name];
    },
  };
}

/**
 * A JSON response. Discovery / jwks are cacheable; userinfo passes an explicit
 * `no-store` via `headers`.
 *
 * @param {number} status
 * @param {Record<string, unknown>} payload
 * @param {Record<string, string>} [headers]
 * @returns {OidcResponse}
 */
export function jsonResponse(status, payload, headers = {}) {
  return {
    status,
    headers: { 'content-type': 'application/json', ...lower(headers) },
    body: JSON.stringify(payload),
  };
}

/**
 * A 302 redirect to `location`.
 *
 * @param {string} location
 * @param {Record<string, string>} [headers]
 * @returns {OidcResponse}
 */
export function redirectResponse(location, headers = {}) {
  return { status: 302, headers: { location, ...lower(headers) }, body: '' };
}

/** @param {Record<string, string>} headers */
function lower(headers) {
  /** @type {Record<string, string>} */
  const out = {};
  for (const [name, value] of Object.entries(headers)) {
    out[name.toLowerCase()] = value;
  }
  return out;
}
