import { SessionError, ErrorCode } from './errors.js';

/**
 * @typedef {object} CookieOptions
 * @property {string} [domain]
 * @property {string} [path='/']
 * @property {boolean} [secure=true]
 * @property {boolean} [httpOnly=true]
 * @property {'lax' | 'strict' | 'none'} [sameSite='lax']
 * @property {number} [maxAge]     Seconds. Sets both `Max-Age=` and `Expires=`.
 * @property {Date} [expires]      Overrides `maxAge` if both provided.
 */

// A very small cookie parser — hand-rolled to keep the base package
// zero-dep. Follows RFC 6265 §5.2 lenient parsing: unknown attributes
// are ignored; malformed segments are skipped rather than throwing.

/**
 * Parse a `Cookie:` request header into a name → value map. Values are
 * URL-decoded per RFC 6265. Duplicate names keep the first occurrence
 * (browsers send at most one value per name, but proxies sometimes fold
 * headers).
 *
 * @param {string | null | undefined} header
 * @returns {Record<string, string>}
 */
export function parseCookies(header) {
  const out = Object.create(null);
  if (typeof header !== 'string' || header.length === 0) {
    return out;
  }
  const parts = header.split(/;\s*/);
  for (const part of parts) {
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
 * Build a `Set-Cookie` header value. Values are URL-encoded, and any
 * attribute violation (bad SameSite, unresolvable secure requirement
 * for `__Host-` prefix) throws `INVALID_ARGUMENT` at boot time so
 * misconfigurations don't slip into production.
 *
 * @param {string} name
 * @param {string} value
 * @param {CookieOptions} [options]
 * @returns {string}
 */
export function serialiseCookie(name, value, options = {}) {
  if (typeof name !== 'string' || name.length === 0) {
    throw new SessionError(ErrorCode.INVALID_ARGUMENT, 'serialiseCookie: name is required');
  }
  if (!/^[!#$%&'*+\-.0-9A-Z^_`a-z|~]+$/.test(name)) {
    throw new SessionError(
      ErrorCode.INVALID_ARGUMENT,
      `serialiseCookie: cookie name '${name}' contains disallowed characters`,
    );
  }
  const sameSite = options.sameSite ?? 'lax';
  if (sameSite !== 'lax' && sameSite !== 'strict' && sameSite !== 'none') {
    throw new SessionError(
      ErrorCode.INVALID_ARGUMENT,
      `serialiseCookie: sameSite must be 'lax' | 'strict' | 'none'; got '${sameSite}'`,
    );
  }
  const secure = options.secure ?? true;
  const httpOnly = options.httpOnly ?? true;
  if (sameSite === 'none' && !secure) {
    throw new SessionError(
      ErrorCode.INVALID_ARGUMENT,
      "serialiseCookie: sameSite='none' requires secure=true (browsers reject it otherwise)",
    );
  }
  // `__Host-` prefix: cookie is only sent to the domain that set it,
  // requires Secure, Path=/, and NO Domain attribute.
  if (name.startsWith('__Host-')) {
    if (!secure) {
      throw new SessionError(
        ErrorCode.INVALID_ARGUMENT,
        `serialiseCookie: cookie name '${name}' uses the __Host- prefix — Secure is mandatory`,
      );
    }
    if (options.domain) {
      throw new SessionError(
        ErrorCode.INVALID_ARGUMENT,
        `serialiseCookie: cookie name '${name}' uses the __Host- prefix — Domain must NOT be set`,
      );
    }
    if (options.path && options.path !== '/') {
      throw new SessionError(
        ErrorCode.INVALID_ARGUMENT,
        `serialiseCookie: cookie name '${name}' uses the __Host- prefix — Path must be '/'`,
      );
    }
  } else if (name.startsWith('__Secure-') && !secure) {
    throw new SessionError(
      ErrorCode.INVALID_ARGUMENT,
      `serialiseCookie: cookie name '${name}' uses the __Secure- prefix — Secure is mandatory`,
    );
  }
  // Attribute values are emitted verbatim — a `;`, comma, or control
  // char inside them would splice extra attributes (or a second cookie)
  // into the header. Config-sourced, so reject loudly at boot.
  if (options.domain !== undefined && !/^[a-zA-Z0-9.-]+$/.test(options.domain)) {
    throw new SessionError(
      ErrorCode.INVALID_ARGUMENT,
      `serialiseCookie: domain contains characters not allowed in a cookie attribute; got ${JSON.stringify(options.domain)}`,
    );
  }
  if (options.path !== undefined && /[;,\s\x00-\x1f\x7f]/.test(options.path)) {
    throw new SessionError(
      ErrorCode.INVALID_ARGUMENT,
      `serialiseCookie: path contains characters not allowed in a cookie attribute; got ${JSON.stringify(options.path)}`,
    );
  }
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.domain) {
    parts.push(`Domain=${options.domain}`);
  }
  parts.push(`Path=${options.path ?? '/'}`);
  const expires = options.expires;
  const maxAge = options.maxAge;
  if (expires instanceof Date) {
    parts.push(`Expires=${expires.toUTCString()}`);
  }
  if (typeof maxAge === 'number' && Number.isFinite(maxAge)) {
    parts.push(`Max-Age=${Math.floor(maxAge)}`);
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
  return serialiseCookie(name, '', {
    ...options,
    maxAge: 0,
    expires: new Date(0),
  });
}
