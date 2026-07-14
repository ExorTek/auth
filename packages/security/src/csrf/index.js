/**
 * CSRF token generation and verification.
 *
 * Recommended pattern: **signed double-submit cookie + custom header**.
 *   1. Server issues `token = generate(secret)` — an unpredictable random
 *      identifier plus an HMAC binding it to the server's secret.
 *   2. Store it in a `__Host-` prefixed cookie (Secure, SameSite=Strict).
 *      NOT HttpOnly if the client echoes it from JavaScript (step 3) —
 *      client-side JS cannot read an HttpOnly cookie. Use HttpOnly only
 *      when the server template-injects the token into forms/meta tags
 *      itself.
 *   3. On every write request (POST/PUT/PATCH/DELETE) the client echoes the
 *      same value in a custom header (or a template-injected form field).
 *   4. `verify(fromCookie, fromHeader, secret)` checks equality *and* the
 *      HMAC — so a planted cookie without knowledge of the secret is useless.
 *
 * `generateUnsigned` / `verifyUnsigned` exist for legacy setups where the
 * server has no signing secret. Prefer `generate` — the unsigned variant
 * cannot detect tampering.
 *
 * `generateForSession` binds the token to a session ID. When the session
 * expires or is rotated, all outstanding tokens are implicitly invalidated.
 */

import { randomBytes, timingSafeEqual } from '../util/bytes.js';
import { encodeBase64Url } from '../util/base64url.js';
import { hmacBase64Url } from '../util/hmac.js';
import { SecurityError, ErrorCode } from '../internal/errors.js';

const DEFAULT_TOKEN_BYTES = 32;

function assertSecret(secret, name) {
  if (typeof secret !== 'string' && !Buffer.isBuffer(secret) && !(secret instanceof Uint8Array)) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `${name} must be a non-empty string or Buffer of at least 32 bytes — got ${secret === null ? 'null' : typeof secret}`,
    );
  }
  const len = typeof secret === 'string' ? Buffer.byteLength(secret) : secret.length;
  if (len < 32) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `${name} must be at least 32 bytes of entropy; got ${len}. Generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"`,
    );
  }
}

/**
 * Generate a signed CSRF token: `<random>.<hmac>`.
 * The random half is the token proper; the HMAC binds it to the server secret
 * so an attacker who plants a fake cookie can't forge the tag.
 *
 * @param {string | Buffer} secret — at least 32 bytes of entropy
 * @param {{ length?: number }} [options]
 * @returns {string}
 */
export function generate(secret, options = {}) {
  assertSecret(secret, 'secret');
  const length = options.length ?? DEFAULT_TOKEN_BYTES;
  if (!Number.isInteger(length) || length < 16 || length > 128) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `options.length must be an integer between 16 and 128 bytes; got ${length}`,
    );
  }
  const random = encodeBase64Url(randomBytes(length));
  const mac = hmacBase64Url(random, secret);
  return `${random}.${mac}`;
}

/**
 * Verify a signed CSRF token. Returns true iff:
 *   - both values are present and structurally valid,
 *   - the two values are identical (timing-safe),
 *   - the HMAC tag matches the current secret.
 *
 * Never throws for invalid input — a malformed or missing token is just an
 * unauthenticated request. Only throws `SecurityError` on programmer error
 * (bad secret).
 *
 * @param {unknown} fromCookie
 * @param {unknown} fromHeader
 * @param {string | Buffer} secret
 * @returns {boolean}
 */
export function verify(fromCookie, fromHeader, secret) {
  assertSecret(secret, 'secret');
  if (typeof fromCookie !== 'string' || typeof fromHeader !== 'string') {
    return false;
  }
  if (!fromCookie || !fromHeader) {
    return false;
  }
  if (!timingSafeEqual(fromCookie, fromHeader)) {
    return false;
  }
  const dot = fromCookie.lastIndexOf('.');
  if (dot <= 0 || dot === fromCookie.length - 1) {
    return false;
  }
  const random = fromCookie.slice(0, dot);
  const tag = fromCookie.slice(dot + 1);
  const expected = hmacBase64Url(random, secret);
  return timingSafeEqual(tag, expected);
}

/**
 * Generate an unsigned random token. Use only when there is no server secret
 * available — the check is a plain equality between cookie and header, so a
 * planted cookie will pass. `generate` is preferred.
 *
 * @param {{ length?: number }} [options]
 * @returns {string}
 */
export function generateUnsigned(options = {}) {
  const length = options.length ?? DEFAULT_TOKEN_BYTES;
  if (!Number.isInteger(length) || length < 16 || length > 128) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `options.length must be an integer between 16 and 128 bytes; got ${length}`,
    );
  }
  return encodeBase64Url(randomBytes(length));
}

/**
 * Verify an unsigned CSRF token — plain timing-safe equality of cookie and
 * form/header value.
 *
 * @param {unknown} fromCookie
 * @param {unknown} fromForm
 * @returns {boolean}
 */
export function verifyUnsigned(fromCookie, fromForm) {
  if (typeof fromCookie !== 'string' || typeof fromForm !== 'string') {
    return false;
  }
  if (!fromCookie || !fromForm) {
    return false;
  }
  return timingSafeEqual(fromCookie, fromForm);
}

/**
 * Generate a session-bound CSRF token: `hmacBase64Url(sessionId, secret)`.
 * Requires no per-request storage — the value is derived from state the
 * server already has. When the session expires, so does the token.
 *
 * @param {string} sessionId — non-empty session identifier
 * @param {string | Buffer} secret
 * @returns {string}
 */
export function generateForSession(sessionId, secret) {
  if (typeof sessionId !== 'string' || sessionId.length === 0) {
    throw new SecurityError(ErrorCode.INVALID_ARGUMENT, 'sessionId must be a non-empty string');
  }
  assertSecret(secret, 'secret');
  return hmacBase64Url(sessionId, secret);
}

/**
 * Verify a session-bound CSRF token against the current session.
 *
 * @param {unknown} token
 * @param {string} sessionId
 * @param {string | Buffer} secret
 * @returns {boolean}
 */
export function verifyForSession(token, sessionId, secret) {
  if (typeof token !== 'string' || typeof sessionId !== 'string' || sessionId.length === 0) {
    return false;
  }
  assertSecret(secret, 'secret');
  return timingSafeEqual(token, hmacBase64Url(sessionId, secret));
}
