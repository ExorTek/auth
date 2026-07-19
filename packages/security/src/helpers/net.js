import { createHmac } from 'node:crypto';
import { timingSafeEqual } from '@exortek/shared/timing-safe';
import { SecurityError, ErrorCode } from '../internal/errors.js';
import { invalidArgument } from '../internal/guards.js';

/**
 * Extract the real client IP from a request-like object, honouring a
 * trust-proxy allowlist. Node behind a load balancer sees the LB's IP
 * in `req.socket.remoteAddress`; the real client sits inside
 * `X-Forwarded-For` — but only reachable safely by walking the header
 * **right-to-left** past the trusted proxy hops, because a client can
 * forge left-most entries and every conforming proxy *appends* the
 * real address.
 *
 * ### `trustProxy` semantics
 *
 * | Value              | Meaning                                                                                     |
 * | ------------------ | ------------------------------------------------------------------------------------------- |
 * | `false` (default)  | Ignore XFF entirely; return `socket.remoteAddress`. Only correct when Node is edge-facing.  |
 * | `true`             | Trust every hop. Returns the left-most XFF entry — **spoofable unless the first proxy strips inbound XFF**. |
 * | `string[]`         | Right-to-left walk skipping entries whose value is in the set; returns the first untrusted hop. |
 *
 * ### `proxyCount`
 *
 * Alternative to `trustProxy: string[]` when the proxy chain depth is
 * known but the addresses aren't stable (e.g. Cloudflare + a k8s
 * ingress). Skips **N** rightmost XFF entries and returns the
 * `(N + 1)`-th from the right — i.e. the last hop before the trusted
 * chain begins. Wins over `trustProxy` when both are set.
 *
 * @param {{
 *   headers?: Record<string, string | string[] | undefined>,
 *   socket?: { remoteAddress?: string },
 *   ip?: string,
 * }} req
 * @param {{
 *   trustProxy?: boolean | string[],
 *   proxyCount?: number,
 *   headers?: string[],
 * }} [options]
 * @returns {string | undefined}
 */
export function getClientIp(req, options = {}) {
  const trustProxy = options.trustProxy ?? false;
  const proxyCount = options.proxyCount;
  const headerNames = options.headers ?? ['x-forwarded-for', 'x-real-ip'];

  const remote = req.socket?.remoteAddress || req.ip;

  if (trustProxy === false && proxyCount === undefined) {
    return remote || undefined;
  }
  const trustedSet = Array.isArray(trustProxy) ? new Set(trustProxy) : null;
  if (trustedSet && remote && !trustedSet.has(remote) && proxyCount === undefined) {
    return remote || undefined;
  }

  for (const name of headerNames) {
    const raw = req.headers?.[name];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (typeof value !== 'string' || value.length === 0) {
      continue;
    }
    const parts = value
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    if (parts.length === 0) {
      continue;
    }

    if (typeof proxyCount === 'number' && proxyCount >= 0) {
      const idx = parts.length - proxyCount - 1;
      return idx >= 0 ? parts[idx] : parts[0];
    }

    if (trustedSet) {
      for (let i = parts.length - 1; i >= 0; i--) {
        if (!trustedSet.has(parts[i])) {
          return parts[i];
        }
      }
      return parts[0]; // every hop trusted — fall back to the original client
    }

    // trustProxy === true → every hop is trusted; the client sits at the
    // left. This is spoofable unless the first proxy strips inbound XFF.
    return parts[0];
  }
  return remote || undefined;
}

/**
 * Parse an `Authorization: Bearer <token>` header. Case-insensitive on the
 * scheme (RFC 7235 §2.1). Returns the token, or `null` when the header is
 * missing / malformed / uses a different scheme.
 *
 * @param {string | undefined | null} headerValue
 * @returns {string | null}
 */
export function bearer(headerValue) {
  if (typeof headerValue !== 'string') {
    return null;
  }
  const idx = headerValue.indexOf(' ');
  if (idx < 0) {
    return null;
  }
  const scheme = headerValue.slice(0, idx).toLowerCase();
  if (scheme !== 'bearer') {
    return null;
  }
  const token = headerValue.slice(idx + 1).trim();
  return token.length ? token : null;
}

/**
 * Defensive Origin / Referer check for state-changing requests. GET / HEAD
 * are usually excluded; POST / PUT / DELETE / PATCH should carry a same-
 * origin `Origin` header (`Referer` as a fallback for older browsers).
 *
 * Complements CORS: CORS controls cross-origin READS, this catches CSRF-
 * like requests where a cookie is present but Origin doesn't match.
 *
 * @param {{
 *   method?: string,
 *   headers?: Record<string, string | undefined>,
 * }} req
 * @param {{
 *   allowedOrigins: Array<string | RegExp>,
 *   safeMethods?: string[],
 * }} options
 * @returns {boolean} true if the request may proceed
 */
export function checkOrigin(req, options) {
  const safe = new Set((options.safeMethods ?? ['GET', 'HEAD', 'OPTIONS']).map(m => m.toUpperCase()));
  if (safe.has(String(req.method || '').toUpperCase())) {
    return true;
  }
  const origin = req.headers?.origin ?? req.headers?.referer;
  if (typeof origin !== 'string' || origin.length === 0) {
    return false;
  }
  let compared;
  try {
    compared = new URL(origin).origin;
  } catch {
    return false;
  }
  for (const rule of options.allowedOrigins) {
    if (typeof rule === 'string' && rule === compared) {
      return true;
    }
    if (rule instanceof RegExp && rule.test(compared)) {
      return true;
    }
  }
  return false;
}

/**
 * Verify a webhook payload against an HMAC signature (constant-time).
 *
 * `signatureHeader` may be the plain hex digest OR a scheme-prefixed
 * variant like `sha256=<hex>` (GitHub convention). Multiple
 * comma-separated candidates are accepted, and any candidate that
 * matches wins.
 *
 * **Deliberately NOT covered:** Stripe-style timestamped envelopes
 * (`t=<ts>,v1=<hex>`). Verifying those correctly requires a
 * `tolerance` window against a replay attacker who resubmits the
 * exact envelope, which is a separate feature — this helper's job
 * is the HMAC comparison, not the freshness policy.
 *
 * @param {string | Buffer} payload    Raw request body — DO NOT stringify JSON first.
 * @param {string} signatureHeader     Value from the incoming signature header.
 * @param {string | Buffer} secret     Shared secret (32 bytes minimum recommended).
 * @param {{ algorithm?: 'sha256' | 'sha512' }} [options]
 *   `algorithm` — HMAC hash. Restricted to `sha256` (default) and
 *   `sha512`; anything else throws. Weaker hashes (`sha1`) are
 *   deliberately not accepted even though `node:crypto` supports them.
 * @returns {boolean}
 */
export function webhookVerify(payload, signatureHeader, secret, options = {}) {
  if (typeof signatureHeader !== 'string' || signatureHeader.length === 0) {
    return false;
  }
  if (!secret || (typeof secret !== 'string' && !Buffer.isBuffer(secret))) {
    throw invalidArgument('webhookVerify.secret must be a non-empty string or Buffer');
  }
  const algorithm = options.algorithm ?? 'sha256';
  if (algorithm !== 'sha256' && algorithm !== 'sha512') {
    throw invalidArgument(
      `webhookVerify.options.algorithm must be 'sha256' or 'sha512'; got ${JSON.stringify(algorithm)}. Weaker hashes are deliberately rejected — request a stronger scheme from the webhook provider if you're stuck on one.`,
    );
  }
  const expected = createHmac(algorithm, secret).update(payload).digest();

  // Collect every plausible candidate. `sha256=<hex>,v1=<hex>` shapes are
  // common enough that a naïve equality check would miss them.
  const candidates = [];
  for (const raw of signatureHeader.split(',')) {
    const trimmed = raw.trim();
    if (!trimmed) {
      continue;
    }
    const eq = trimmed.indexOf('=');
    if (eq > 0) {
      candidates.push(trimmed.slice(eq + 1));
    }
    candidates.push(trimmed);
  }
  for (const cand of candidates) {
    if (!/^[0-9a-fA-F]+$/.test(cand)) {
      continue;
    }
    let actual;
    try {
      actual = Buffer.from(cand, 'hex');
    } catch {
      continue;
    }
    if (timingSafeEqual(actual, expected)) {
      return true;
    }
  }
  return false;
}
