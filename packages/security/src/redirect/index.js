import { isArray, isString } from '@exortek/shared/predicates';

import { SecurityError, ErrorCode } from '../internal/errors.js';

/**
 * @typedef {object} SafeRedirectOptions
 * @property {string} [defaultTo='/']
 *   Where to send the user when the input fails validation. Must itself be
 *   a safe target — validated on option parse.
 * @property {Array<string> | string} [allowedHosts]
 *   Hostnames (case-insensitive) that are trusted external targets. Use a
 *   leading `*.` for subdomain wildcards: `*.example.com` matches
 *   `app.example.com` and `sub.app.example.com` but NOT `example.com`
 *   itself. Absolute URLs whose hostname doesn't match any entry are
 *   rejected. Omit to disallow all absolute URLs.
 * @property {Array<string>} [allowedSchemes=['http','https']]
 *   Schemes permitted on absolute URLs. `javascript:` / `data:` / `vbscript:`
 *   are ALWAYS rejected regardless of this option — a bug in your allowlist
 *   shouldn't turn into XSS.
 * @property {boolean} [allowRelative=true]
 *   Whether same-origin paths (`/foo`, `/foo?bar`) are accepted. Turn off
 *   for flows where you want an explicit allowlist even for internal URLs.
 */

/**
 * @typedef {object} SafeRedirectResult
 * @property {boolean} safe    True if the input was accepted; false when
 *                             the returned `url` is the fallback.
 * @property {string}  url     The URL you should redirect to.
 * @property {string}  [reason] When unsafe, a short code explaining why
 *                             (`'empty' | 'illegal-chars' | 'protocol-relative'
 *                              | 'malformed' | 'scheme' | 'userinfo' | 'host'
 *                              | 'relative-not-allowed'`). Useful for logging.
 */

// Schemes that are UNCONDITIONALLY dangerous. Even if a caller misconfigures
// their allowlist to include one of these, `safeRedirect` still refuses —
// silently swapping an XSS vector into the fallback URL is safer than
// respecting the option verbatim.
const HARD_BAN_SCHEMES = new Set(['javascript', 'data', 'vbscript', 'file', 'blob']);
const DEFAULT_ALLOWED_SCHEMES = ['http', 'https'];

function normalizeHosts(hosts) {
  if (hosts === undefined || hosts === null) {
    return null;
  }
  const list = isArray(hosts) ? hosts : [hosts];
  return list.map(h => {
    if (typeof h !== 'string' || h.length === 0) {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        `safeRedirect: allowedHosts entries must be non-empty strings; got ${JSON.stringify(h)}`,
      );
    }
    return h.toLowerCase();
  });
}

function hostMatches(hostname, pattern) {
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1); // '.example.com'
    return hostname.endsWith(suffix) && hostname.length > suffix.length;
  }
  return hostname === pattern;
}

function isAbsoluteUrl(input) {
  // Absolute URLs start with a scheme like `https:` or `mailto:`. Case-
  // insensitive per RFC 3986. Reject inputs that only look like they have
  // a scheme (e.g. `javascript:alert(1)`) later; here we just detect shape.
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(input);
}

function unsafe(defaultTo, reason) {
  return { safe: false, url: defaultTo, reason };
}

/**
 * Guard against open-redirect abuse.
 *
 * Given a user-supplied redirect target (e.g. `?next=...`), return either
 * that target (if it passes every check) or a safe fallback. Never trust
 * the input value on its own — always redirect to `result.url`.
 *
 *   const result = safeRedirect(req.query.next, {
 *     allowedHosts: ['app.example.com', '*.example.com'],
 *     defaultTo: '/dashboard',
 *   })
 *   if (!result.safe) log.warn({ reason: result.reason, next: req.query.next })
 *   res.redirect(result.url)
 *
 * Rejected inputs (the returned `reason` codes):
 *   - `empty`               — missing / non-string
 *   - `illegal-chars`       — whitespace, control chars, backslashes
 *   - `protocol-relative`   — `//evil.com/foo` (browsers resolve to host)
 *   - `relative-not-allowed`— path input while `allowRelative: false`
 *   - `malformed`           — URL constructor threw
 *   - `scheme`              — scheme not in allowlist, or hard-banned
 *   - `userinfo`            — `https://evil@safe.com` phishing trick
 *   - `host`                — hostname not in `allowedHosts`
 *
 * @param {unknown} input                           The user-supplied redirect target.
 * @param {SafeRedirectOptions} [options]
 * @returns {SafeRedirectResult}
 */
export function safeRedirect(input, options = {}) {
  const defaultTo = options.defaultTo ?? '/';
  const allowedSchemes = new Set((options.allowedSchemes ?? DEFAULT_ALLOWED_SCHEMES).map(s => s.toLowerCase()));
  const allowedHosts = normalizeHosts(options.allowedHosts);
  const allowRelative = options.allowRelative !== false;

  // Even the fallback shouldn't be attacker-friendly — reject configs that
  // set a defaultTo we ourselves wouldn't produce.
  if (typeof defaultTo !== 'string' || !defaultTo.startsWith('/')) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `safeRedirect: defaultTo must be a same-origin path starting with '/'; got ${JSON.stringify(defaultTo)}`,
    );
  }

  if (typeof input !== 'string' || input.length === 0) {
    return unsafe(defaultTo, 'empty');
  }

  // Any whitespace, control char, or backslash disqualifies the input.
  // Whitespace can smuggle a scheme prefix past naive checks; backslashes
  // are treated as forward-slashes by some browsers on Windows.
  if (/[\x00-\x1f\s\\]/.test(input)) {
    return unsafe(defaultTo, 'illegal-chars');
  }

  // Protocol-relative URLs (`//evil.com/x`) look like paths but browsers
  // send you cross-origin. Reject with prejudice.
  if (input.startsWith('//')) {
    return unsafe(defaultTo, 'protocol-relative');
  }

  // Same-origin relative URL — must start with a single `/`.
  if (input.startsWith('/')) {
    return allowRelative ? { safe: true, url: input } : unsafe(defaultTo, 'relative-not-allowed');
  }

  if (!isAbsoluteUrl(input)) {
    // Bare token like `foo/bar` — ambiguous, could be a relative-to-current
    // path. We refuse; callers who genuinely want that can prepend `/`.
    return unsafe(defaultTo, 'malformed');
  }

  let parsed;
  try {
    parsed = new URL(input);
  } catch {
    return unsafe(defaultTo, 'malformed');
  }

  const scheme = parsed.protocol.slice(0, -1).toLowerCase(); // strip trailing ':'
  if (HARD_BAN_SCHEMES.has(scheme) || !allowedSchemes.has(scheme)) {
    return unsafe(defaultTo, 'scheme');
  }

  // https://evil.com@app.example.com/… — the browser navigates to
  // app.example.com, but a naive log or UI shows `evil.com` first.
  // We never accept userinfo, whether or not the host is in the allowlist.
  if (parsed.username || parsed.password) {
    return unsafe(defaultTo, 'userinfo');
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!allowedHosts || !allowedHosts.some(p => hostMatches(hostname, p))) {
    return unsafe(defaultTo, 'host');
  }

  return { safe: true, url: parsed.toString() };
}

/**
 * @typedef {object} ExtractReturnUrlOptions
 * @property {string[]} [queryParams=['next','return_to','returnTo','redirect','redirect_uri']]
 *   Query param names to check, in priority order.
 * @property {string | string[]} [headerName]
 *   Header name(s) to fall back to (e.g. `'x-return-to'`). Case-insensitive.
 * @property {string} [cookieName]
 *   Cookie name to check as a last resort. Requires cookies to be
 *   pre-parsed onto `req.cookies` (adapter middleware does this).
 */

/**
 * Pick the user-supplied "come back to" URL from wherever the client
 * stashed it — query string, header, or cookie. Returns the first
 * non-empty candidate. Does NOT validate — pipe the result into
 * `safeRedirect` before actually redirecting:
 *
 *   const raw = extractReturnUrl(req, {
 *     queryParams: ['next', 'return_to'],
 *     headerName: 'x-return-to',
 *   })
 *   const { safe, url } = safeRedirect(raw, { allowedHosts: [...] })
 *   res.redirect(url)
 *
 * @param {{
 *   query?: Record<string, unknown>,
 *   headers?: Record<string, string | string[] | undefined>,
 *   cookies?: Record<string, string | undefined>,
 * }} req
 * @param {ExtractReturnUrlOptions} [options]
 * @returns {string | undefined}
 */
export function extractReturnUrl(req, options = {}) {
  const queryParams = options.queryParams ?? ['next', 'return_to', 'returnTo', 'redirect', 'redirect_uri'];
  const q = req.query ?? {};
  for (const name of queryParams) {
    const value = q[name];
    // Take the first entry when frameworks parse query params as arrays.
    const scalar = isArray(value) ? value[0] : value;
    if (isString(scalar) && scalar.length > 0) {
      return scalar;
    }
  }

  if (options.headerName) {
    const headerNames = isArray(options.headerName) ? options.headerName : [options.headerName];
    for (const name of headerNames) {
      const raw = req.headers?.[name.toLowerCase()];
      const scalar = isArray(raw) ? raw[0] : raw;
      if (isString(scalar) && scalar.length > 0) {
        return scalar;
      }
    }
  }

  if (options.cookieName && req.cookies) {
    const c = req.cookies[options.cookieName];
    if (isString(c) && c.length > 0) {
      return c;
    }
  }

  return undefined;
}

/**
 * Compare two URLs by origin (scheme + host + port). Uses WHATWG URL
 * parsing so `https://example.com` and `https://example.com:443/foo`
 * compare equal. Returns `false` on any parse failure — never throws.
 *
 * Complements `checkOrigin`, which reads `Origin` / `Referer` headers off
 * a request. `isSameOrigin` is the primitive both callers land on when
 * they need direct URL-to-URL comparison (OAuth callback validation,
 * Referer-based flow checks, allowlist-of-one matching).
 *
 * @param {string | URL | undefined | null} a
 * @param {string | URL | undefined | null} b
 * @returns {boolean}
 */
export function isSameOrigin(a, b) {
  if (a == null || b == null) {
    return false;
  }
  try {
    const oa = a instanceof URL ? a.origin : new URL(a).origin;
    const ob = b instanceof URL ? b.origin : new URL(b).origin;
    return oa === ob;
  } catch {
    return false;
  }
}
