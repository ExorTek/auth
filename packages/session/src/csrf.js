import { createHmac, randomBytes } from 'node:crypto';
import { timingSafeEqual } from '@exortek/shared/timing-safe';
import { SessionError, ErrorCode } from './errors.js';
import { assertNonEmptyString, invalidArgument } from './internal/guards.js';

// CSRF token derivation from a session ID + a server secret. The token
// is deterministic given the same session — clients can safely round-trip
// it through hidden form fields, meta tags, or a non-HttpOnly cookie —
// and stateless to verify: no store lookup needed, just HMAC recomputation.
//
// This is the standard "synchroniser token" pattern hardened by binding
// the token to the session it belongs to, so an attacker who steals a
// CSRF value from one user cannot use it against another.
//
// BREACH note: the derived token is constant for the session's
// lifetime. If you embed it in HTML served with response compression,
// a BREACH-class attacker can recover it byte-by-byte. Wrap it with
// {@link maskCsrfToken} before rendering — each response then carries
// a different ciphertext of the same underlying token — and call
// {@link unmaskCsrfToken} before {@link verifyCsrfToken}.

const NAMESPACE = Buffer.from('exortek/session/csrf/v1', 'utf8');
const MIN_SECRET_BYTES = 32;

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
  assertNonEmptyString(sessionId, 'deriveCsrfToken.sessionId');
  if (typeof secret !== 'string' && !Buffer.isBuffer(secret) && !(secret instanceof Uint8Array)) {
    throw invalidArgument('deriveCsrfToken.secret must be a string / Buffer / Uint8Array');
  }
  const key = typeof secret === 'string' ? Buffer.from(secret, 'utf8') : Buffer.from(secret);
  if (key.byteLength < MIN_SECRET_BYTES) {
    throw invalidArgument(
      `deriveCsrfToken.secret must be at least ${MIN_SECRET_BYTES} bytes (got ${key.byteLength})`,
    );
  }
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
  // The shared compare is length-safe: a length mismatch burns a
  // comparison and returns false instead of short-circuiting, so
  // "wrong length" is not distinguishable from "wrong value".
  return timingSafeEqual(Buffer.from(expected, 'utf8'), Buffer.from(candidate, 'utf8'));
}

/**
 * One-time-pad mask a CSRF token for embedding in compressed HTML
 * (BREACH mitigation, per OWASP). Output is `base64url(pad ‖ pad⊕token)`
 * — a fresh random pad per call, so two renders of the same token never
 * produce the same bytes.
 *
 * @param {string} token    Output of {@link deriveCsrfToken}.
 * @returns {string}
 */
export function maskCsrfToken(token) {
  assertNonEmptyString(token, 'maskCsrfToken.token');
  const t = Buffer.from(token, 'utf8');
  const pad = randomBytes(t.length);
  const masked = Buffer.alloc(t.length);
  for (let i = 0; i < t.length; i++) {
    masked[i] = t[i] ^ pad[i];
  }
  return Buffer.concat([pad, masked]).toString('base64url');
}

/**
 * Reverse {@link maskCsrfToken}. Returns the underlying token, or
 * `null` for malformed input — never throws for user-supplied values.
 * Feed the result into {@link verifyCsrfToken}.
 *
 * @param {unknown} masked
 * @returns {string | null}
 */
export function unmaskCsrfToken(masked) {
  if (typeof masked !== 'string' || masked.length === 0) {
    return null;
  }
  let bytes;
  try {
    bytes = Buffer.from(masked, 'base64url');
  } catch {
    return null;
  }
  if (bytes.length === 0 || bytes.length % 2 !== 0) {
    return null;
  }
  const half = bytes.length / 2;
  const out = Buffer.alloc(half);
  for (let i = 0; i < half; i++) {
    out[i] = bytes[i] ^ bytes[half + i];
  }
  return out.toString('utf8');
}
