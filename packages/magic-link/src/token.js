/**
 * Token codec for `@exortek/magic-link`.
 *
 * Format:
 *
 *     <prefix>.<base64url(JSON payload)>.<base64url(HMAC-SHA256 tag)>
 *
 * Payload is intentionally minimal — `{ id, iat, exp, eh? }`:
 *
 * - `id`  — 128-bit random. Used as the store lookup key for
 *   single-use enforcement. Not a secret on its own; the HMAC gates
 *   authenticity.
 * - `iat` / `exp` — seconds since epoch. Enforced on verify.
 * - `eh`  — optional SHA-256 of the email + a salt derived from the
 *   HMAC secret. Present when `hashEmail: true` (default). Lets
 *   `verifyMagicLink` short-circuit a wrong-email reject before ever
 *   touching the store; also gives us cross-check against a poisoned
 *   store row.
 *
 * The email itself never appears in the URL — only in the store.
 * `redirectTo` (if any) also stays in the store, not the URL, so it
 * cannot be tampered with by editing the link.
 *
 * Default prefix is {@link DEFAULT_PREFIX} (`mlink_v1`). Callers may
 * override it (e.g. `'login_v1'`) — the same prefix must be used at
 * create and verify time or verification returns `reason: 'malformed'`.
 */

import { createHmac, randomBytes } from 'node:crypto';
import * as b64u from '@exortek/shared/base64url';
import { isObject, isString } from '@exortek/shared/predicates';
import { timingSafeEqual } from '@exortek/shared/timing-safe';

export const DEFAULT_PREFIX = 'mlink_v1';
const HMAC_ALG = 'sha256';

// Printable ASCII, no `.` (delimiter), no whitespace. Length capped so
// a misused prefix can't grow the token unboundedly.
const PREFIX_RE = /^[A-Za-z0-9_-]{1,32}$/;

/**
 * @param {string} prefix
 * @param {string} name
 * @param {(msg: string) => Error} invalidArg
 * @returns {string}
 */
export function assertPrefix(prefix, name, invalidArg) {
  if (!isString(prefix) || !PREFIX_RE.test(prefix)) {
    throw invalidArg(
      `${name} must match /^[A-Za-z0-9_-]{1,32}$/ (letters, digits, '_' or '-', 1-32 chars — no '.' since it's the token delimiter); got ${JSON.stringify(prefix)}`,
    );
  }
  return prefix;
}

/**
 * Random 128-bit id encoded as 22 base64url characters. Used as the
 * store key for single-use enforcement, so it must be unpredictable
 * and unique per link.
 *
 * @returns {string}
 */
export function newId() {
  return b64u.encode(randomBytes(16));
}

/**
 * Compute the `eh` (email hash) claim: `SHA-256(secret ‖ email)` in
 * base64url. Not a KDF — email is a low-entropy identifier and the
 * whole payload is HMAC-signed, so a fast hash is enough. The
 * secret-derived namespacing keeps two apps' hashes distinct even
 * for the same email address.
 *
 * @param {Buffer} secret
 * @param {string} email
 * @returns {string}
 */
export function hashEmailValue(secret, email) {
  const h = createHmac(HMAC_ALG, secret).update(email).digest();
  return b64u.encode(h);
}

/**
 * Sign a payload with `secret` and return the compact token string.
 *
 * @param {object} payload
 * @param {Buffer} secret     32+ raw bytes; caller validates length.
 * @param {string} [prefix]   Defaults to {@link DEFAULT_PREFIX}.
 * @returns {string}
 */
export function sign(payload, secret, prefix = DEFAULT_PREFIX) {
  const body = `${prefix}.${b64u.encodeJson(payload)}`;
  const tag = createHmac(HMAC_ALG, secret).update(body).digest();
  return `${body}.${b64u.encode(tag)}`;
}

/**
 * Parse + HMAC-verify a token. Returns the decoded payload on success,
 * or a reason string on any failure. Never throws.
 *
 * @param {string} token
 * @param {Buffer} secret
 * @param {string} [prefix]
 * @returns {{ payload: object } | { reason: 'malformed' | 'bad_signature' }}
 */
export function decode(token, secret, prefix = DEFAULT_PREFIX) {
  if (!isString(token) || token.length === 0) {
    return { reason: 'malformed' };
  }
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== prefix) {
    return { reason: 'malformed' };
  }
  const [, encodedPayload, encodedTag] = parts;
  let tag;
  try {
    tag = b64u.decode(encodedTag);
  } catch {
    return { reason: 'malformed' };
  }
  const expected = createHmac(HMAC_ALG, secret).update(`${prefix}.${encodedPayload}`).digest();
  if (!timingSafeEqual(tag, expected)) {
    return { reason: 'bad_signature' };
  }
  let payload;
  try {
    payload = b64u.decodeJson(encodedPayload);
  } catch {
    return { reason: 'malformed' };
  }
  if (!isObject(payload)) {
    return { reason: 'malformed' };
  }
  return { payload };
}
