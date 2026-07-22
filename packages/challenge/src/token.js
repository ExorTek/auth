/**
 * Token codec for `@exortek/challenge`.
 *
 * Format:
 *
 *     <prefix>.<base64url(JSON payload)>.<base64url(HMAC-SHA256 tag)>
 *
 * The default prefix is {@link DEFAULT_PREFIX} (`chall_v1`) — deliberately
 * unlike a JWT so the two token families cannot be confused at a call
 * site. Callers may override it (e.g. `'server_challenge'`,
 * `'myapp_v1'`) to brand the wire format for a specific service; the
 * same prefix must be used at create and verify time, or verification
 * returns `reason: 'malformed'`.
 *
 * HMAC covers `<prefix>.<b64u payload>` — the same string the caller
 * received minus the trailing tag. Any change to prefix or payload
 * invalidates the signature; a token minted with one prefix cannot be
 * accepted under another even by the same secret.
 */

import { createHmac, randomBytes } from 'node:crypto';
import * as b64u from '@exortek/shared/base64url';
import { isObject, isString } from '@exortek/shared/predicates';
import { timingSafeEqual } from '@exortek/shared/timing-safe';

export const DEFAULT_PREFIX = 'chall_v1';
const HMAC_ALG = 'sha256';

// Printable ASCII, no `.` (delimiter), no whitespace. Length capped so a
// misused prefix can't grow the token unboundedly.
const PREFIX_RE = /^[A-Za-z0-9_-]{1,32}$/;

/**
 * Assert a prefix is well-shaped. Throws via the caller's `invalidArg`
 * function so `createChallenge` / `verifyChallenge` can raise
 * `ChallengeError` with the right code — this module stays free of the
 * error class dependency.
 *
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
 * Random ID for the token's `jti` claim — 128 bits of entropy, encoded
 * as 22 base64url characters. Used as the store key for single-use
 * enforcement, so it must be unpredictable and unique per token.
 *
 * @returns {string}
 */
export function newJti() {
  return b64u.encode(randomBytes(16));
}

/**
 * Sign a payload with `secret` and return the compact token string.
 *
 * @param {object} payload
 * @param {Buffer} secret     32+ raw bytes; caller validates length.
 * @param {string} [prefix]   Wire prefix; defaults to {@link DEFAULT_PREFIX}.
 * @returns {string}
 */
export function sign(payload, secret, prefix = DEFAULT_PREFIX) {
  const body = `${prefix}.${b64u.encodeJson(payload)}`;
  const tag = createHmac(HMAC_ALG, secret).update(body).digest();
  return `${body}.${b64u.encode(tag)}`;
}

/**
 * Parse + HMAC-verify a token. Returns the decoded payload on success,
 * or a reason string on any failure. Never throws on user-input
 * problems — a wrong token is a normal auth outcome.
 *
 * @param {string} token
 * @param {Buffer} secret
 * @param {string} [prefix]   Expected prefix; defaults to {@link DEFAULT_PREFIX}.
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
