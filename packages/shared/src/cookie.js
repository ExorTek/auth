/**
 * RFC 6265 cookie parser + Set-Cookie serialiser. The single
 * implementation behind every `@exortek/*` package that touches the
 * cookie header — session's `cookie.js` and security's CSRF /
 * rate-limit middleware used to carry two subtly divergent copies.
 *
 * Parser is lenient (§5.2): unknown attributes ignored, malformed
 * segments skipped, values URL-decoded, first occurrence wins on
 * duplicate names.
 *
 * Serialiser is strict on **attributes** — a bad SameSite, an
 * unresolvable `__Host-` / `__Secure-` prefix requirement, or a
 * `;` / `,` / control char inside `Domain` / `Path` throws so
 * misconfiguration fails at boot rather than silently splicing a
 * second attribute (or a second cookie) into the header.
 *
 * Errors are plain `Error` — consumers wrap into their typed error
 * class at the surface, same convention as every other shared module.
 */

/**
 * @typedef {object} CookieOptions
 * @property {string} [domain]
 * @property {string} [path='/']
 * @property {boolean} [secure=true]
 * @property {boolean} [httpOnly=true]
 * @property {'lax' | 'strict' | 'none'} [sameSite='lax']
 * @property {number} [maxAge]     Seconds.
 * @property {Date} [expires]
 */

const TOKEN_RE = /^[!#$%&'*+\-.0-9A-Z^_`a-z|~]+$/;
const DOMAIN_RE = /^[a-zA-Z0-9.-]+$/;

const PATH_UNSAFE_RE = /[;,\s\x00-\x1f\x7f]/;

/**
 * Parse a `Cookie:` request header into a name → value map. Values are
 * URL-decoded per RFC 6265. Duplicate names keep the first occurrence
 * (browsers send at most one value per name, but proxies sometimes
 * fold headers).
 *
 * @param {string | null | undefined} header
 * @returns {Record<string, string>}
 */
export function parseCookies(header) {
  const out = Object.create(null);
  if (typeof header !== 'string' || header.length === 0) {
    return out;
  }
  for (const part of header.split(/;\s*/)) {
    const eq = part.indexOf('=');
    if (eq <= 0) {
      continue;
    }
    const name = part.slice(0, eq).trim();
    if (!name || out[name] !== undefined) {
      continue;
    }
    let value = part.slice(eq + 1).trim();
    // Quoted values (rare, but RFC 6265 allows them). Strip the quotes
    // before decoding.
    if (value.length >= 2 && value[0] === '"' && value[value.length - 1] === '"') {
      value = value.slice(1, -1);
    }
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      // Malformed percent encoding — keep the raw value rather than
      // dropping. Callers using base64url tokens will still parse.
      out[name] = value;
    }
  }
  return out;
}

/**
 * Build a `Set-Cookie` header value. Value is URL-encoded; attribute
 * violations throw at boot time.
 *
 * @param {string} name
 * @param {string} value
 * @param {CookieOptions} [options]
 * @returns {string}
 * @throws {Error} on missing/invalid name, bad sameSite, __Host-/
 *                 __Secure- prefix violation, or unsafe Domain/Path.
 */
export function serialiseCookie(name, value, options = {}) {
  if (typeof name !== 'string' || name.length === 0) {
    throw new Error('serialiseCookie: name is required');
  }
  if (!TOKEN_RE.test(name)) {
    throw new Error(`serialiseCookie: cookie name '${name}' contains disallowed characters`);
  }
  const sameSite = options.sameSite ?? 'lax';
  if (sameSite !== 'lax' && sameSite !== 'strict' && sameSite !== 'none') {
    throw new Error(`serialiseCookie: sameSite must be 'lax' | 'strict' | 'none'; got '${sameSite}'`);
  }
  const secure = options.secure ?? true;
  const httpOnly = options.httpOnly ?? true;
  if (sameSite === 'none' && !secure) {
    throw new Error("serialiseCookie: sameSite='none' requires secure=true (browsers reject it otherwise)");
  }
  // `__Host-` prefix: cookie is only sent to the domain that set it,
  // requires Secure, Path=/, and NO Domain attribute.
  if (name.startsWith('__Host-')) {
    if (!secure) {
      throw new Error(`serialiseCookie: cookie name '${name}' uses the __Host- prefix — Secure is mandatory`);
    }
    if (options.domain) {
      throw new Error(`serialiseCookie: cookie name '${name}' uses the __Host- prefix — Domain must NOT be set`);
    }
    if (options.path && options.path !== '/') {
      throw new Error(`serialiseCookie: cookie name '${name}' uses the __Host- prefix — Path must be '/'`);
    }
  } else if (name.startsWith('__Secure-') && !secure) {
    throw new Error(`serialiseCookie: cookie name '${name}' uses the __Secure- prefix — Secure is mandatory`);
  }
  // Attribute values are emitted verbatim — a `;`, comma, or control
  // char inside them would splice extra attributes into the header.
  if (options.domain !== undefined && !DOMAIN_RE.test(options.domain)) {
    throw new Error(
      `serialiseCookie: domain contains characters not allowed in a cookie attribute; got ${JSON.stringify(options.domain)}`,
    );
  }
  if (options.path !== undefined && PATH_UNSAFE_RE.test(options.path)) {
    throw new Error(
      `serialiseCookie: path contains characters not allowed in a cookie attribute; got ${JSON.stringify(options.path)}`,
    );
  }
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.domain) {
    parts.push(`Domain=${options.domain}`);
  }
  parts.push(`Path=${options.path ?? '/'}`);
  if (options.expires !== undefined) {
    if (!(options.expires instanceof Date) || Number.isNaN(+options.expires)) {
      throw new Error(
        `serialiseCookie: expires must be a valid Date; got ${
          options.expires instanceof Date ? 'Invalid Date' : JSON.stringify(options.expires)
        }`,
      );
    }
    parts.push(`Expires=${options.expires.toUTCString()}`);
  }
  if (typeof options.maxAge === 'number' && Number.isFinite(options.maxAge)) {
    parts.push(`Max-Age=${Math.floor(options.maxAge)}`);
  }
  if (secure) {
    parts.push('Secure');
  }
  if (httpOnly) {
    parts.push('HttpOnly');
  }
  parts.push(`SameSite=${sameSite[0].toUpperCase()}${sameSite.slice(1)}`);
  return parts.join('; ');
}

/**
 * Build a `Set-Cookie` value that instructs the browser to delete the
 * cookie — the standard `Max-Age=0` + `Expires=` in the past pair.
 *
 * @param {string} name
 * @param {CookieOptions} [options]
 * @returns {string}
 */
export function serialiseDeleteCookie(name, options = {}) {
  return serialiseCookie(name, '', { ...options, maxAge: 0, expires: new Date(0) });
}
