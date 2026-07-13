/**
 * Extract a session token from an incoming request. Checks, in order:
 *
 *   1. `Authorization: Bearer <token>` header (or a custom header /
 *      prefix per {@link HeaderTokenConfig})
 *   2. The named cookie (parsed from the `Cookie:` header)
 *
 * Returns the raw token string or `undefined` if neither source has it.
 * The framework middleware wraps this to plug into whatever shape
 * `req.headers` takes on that platform.
 */

/**
 * @typedef {object} HeaderTokenConfig
 * @property {string} [headerName='Authorization']
 * @property {string} [prefix='Bearer ']
 */

/**
 * @param {Record<string, string | string[] | undefined>} headers
 *   A dictionary-shaped header source. Case-insensitive lookup — Node
 *   HTTP delivers lowercased keys, WHATWG `Headers.get(name)` does its
 *   own case-folding; we just try both spellings.
 * @param {HeaderTokenConfig} [config]
 * @returns {string | undefined}
 */
export function extractTokenFromHeader(headers, config = {}) {
  if (!headers) {
    return undefined;
  }
  const headerName = (config.headerName ?? 'Authorization').toLowerCase();
  const prefix = config.prefix ?? 'Bearer ';
  const value = readHeader(headers, headerName);
  if (typeof value !== 'string' || value.length === 0) {
    return undefined;
  }
  if (prefix && !value.startsWith(prefix)) {
    return undefined;
  }
  const token = value.slice(prefix.length).trim();
  return token.length > 0 ? token : undefined;
}

function readHeader(headers, lowered) {
  // Node http.IncomingMessage delivers lowercased keys; browsers via
  // `Headers.get()` also lowercase. WHATWG Request objects, on the
  // other hand, expose `.get` — the callers pass either a plain object
  // OR the get result already.
  if (typeof headers.get === 'function') {
    const v = headers.get(lowered);
    if (v !== null && v !== undefined) {
      return Array.isArray(v) ? v[0] : v;
    }
    // Fallback for cases where callers built a lowercased dict
    // themselves.
    return undefined;
  }
  const v = headers[lowered] ?? headers[capitalise(lowered)];
  return Array.isArray(v) ? v[0] : v;
}

function capitalise(name) {
  return name
    .split('-')
    .map(p => (p ? p[0].toUpperCase() + p.slice(1) : p))
    .join('-');
}
