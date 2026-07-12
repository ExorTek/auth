import { createHmac, timingSafeEqual } from 'node:crypto';
import { SecurityError, ErrorCode } from '../internal/errors.js';

/**
 * Extract the real client IP from a request-like object, honouring a
 * trust-proxy allowlist. Node behind a load balancer sees the LB's IP in
 * `req.socket.remoteAddress`; the real client sits in the LEFT-most entry
 * of `X-Forwarded-For` — but only if the request actually came from a
 * trusted proxy (otherwise the header is attacker-controlled).
 *
 * @param {{
 *   headers?: Record<string, string | string[] | undefined>,
 *   socket?: { remoteAddress?: string },
 *   ip?: string,
 * }} req
 * @param {{
 *   trustProxy?: boolean | string[],
 *   headers?: string[],
 * }} [options]
 * @returns {string | undefined}
 */
export function getClientIp(req, options = {}) {
  const trustProxy = options.trustProxy ?? false;
  const headerNames = options.headers ?? ['x-forwarded-for', 'x-real-ip'];

  const remote = req.socket?.remoteAddress || req.ip;

  if (trustProxy === false) {
    return remote || undefined;
  }
  const trusted = trustProxy === true ? true : Array.isArray(trustProxy) ? new Set(trustProxy) : true;
  if (trusted !== true && remote && !trusted.has(remote)) {
    return remote || undefined;
  }

  for (const name of headerNames) {
    const raw = req.headers?.[name];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (typeof value === 'string' && value.length > 0) {
      // Left-most entry is the original client; subsequent are downstream proxies.
      const first = value.split(',')[0].trim();
      if (first) {
        return first;
      }
    }
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
 * variant like `sha256=<hex>` (GitHub / Stripe convention). Multiple
 * comma-separated candidates are accepted — matches Stripe's rotation
 * envelope `t=<ts>,v1=<hex>`. Any candidate that matches wins.
 *
 * @param {string | Buffer} payload    Raw request body — DO NOT stringify JSON first.
 * @param {string} signatureHeader     Value from the incoming signature header.
 * @param {string | Buffer} secret     Shared secret (32 bytes minimum recommended).
 * @param {{ algorithm?: string, scheme?: string }} [options]
 * @returns {boolean}
 */
export function webhookVerify(payload, signatureHeader, secret, options = {}) {
  if (typeof signatureHeader !== 'string' || signatureHeader.length === 0) {
    return false;
  }
  if (!secret || (typeof secret !== 'string' && !Buffer.isBuffer(secret))) {
    throw new SecurityError(ErrorCode.INVALID_ARGUMENT, 'webhookVerify: secret is required');
  }
  const algorithm = options.algorithm ?? 'sha256';
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
    if (actual.length === expected.length && timingSafeEqual(actual, expected)) {
      return true;
    }
  }
  return false;
}
