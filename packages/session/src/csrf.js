import { createHmac, timingSafeEqual } from 'node:crypto';
import { SessionError, ErrorCode } from './errors.js';

// CSRF token derivation from a session ID + a server secret. The token
// is deterministic given the same session — clients can safely round-trip
// it through hidden form fields, meta tags, or a non-HttpOnly cookie —
// and stateless to verify: no store lookup needed, just HMAC recomputation.
//
// This is the standard "synchroniser token" pattern hardened by binding
// the token to the session it belongs to, so an attacker who steals a
// CSRF value from one user cannot use it against another.

const NAMESPACE = Buffer.from('exortek/session/csrf/v1', 'utf8');

/**
 * Derive a CSRF token from a session ID + a server-side secret. The
 * output is a base64url string safe for cookies, form fields, and JSON
 * bodies.
 *
 * @param {string} sessionId
 * @param {string | Buffer | Uint8Array} secret
 * @returns {string}
 */
export function deriveCsrfToken(sessionId, secret) {
  if (typeof sessionId !== 'string' || sessionId.length === 0) {
    throw new SessionError(ErrorCode.INVALID_ARGUMENT, 'deriveCsrfToken: sessionId is required');
  }
  if (typeof secret !== 'string' && !Buffer.isBuffer(secret) && !(secret instanceof Uint8Array)) {
    throw new SessionError(ErrorCode.INVALID_ARGUMENT, 'deriveCsrfToken: secret must be a string / Buffer / Uint8Array');
  }
  const key = typeof secret === 'string' ? Buffer.from(secret, 'utf8') : Buffer.from(secret);
  return createHmac('sha256', key).update(NAMESPACE).update(sessionId).digest('base64url').slice(0, 32);
}

/**
 * Constant-time verify a candidate CSRF token against a session ID +
 * secret pair. Returns `false` on any mismatch, including malformed
 * input — never throws for user-supplied values.
 *
 * @param {unknown} candidate
 * @param {string} sessionId
 * @param {string | Buffer | Uint8Array} secret
 * @returns {boolean}
 */
export function verifyCsrfToken(candidate, sessionId, secret) {
  if (typeof candidate !== 'string' || candidate.length === 0) {
    return false;
  }
  let expected;
  try {
    expected = deriveCsrfToken(sessionId, secret);
  } catch {
    return false;
  }
  if (expected.length !== candidate.length) {
    return false;
  }
  return timingSafeEqual(Buffer.from(expected, 'utf8'), Buffer.from(candidate, 'utf8'));
}
