/**
 * Token codec for `@exortek/challenge`.
 *
 * Format:
 *
 *     chall_v1.<base64url(JSON payload)>.<base64url(HMAC-SHA256 tag)>
 *
 * Not a JWT — deliberately different so the two token families cannot
 * be confused for one another at a call site. The `chall_v1` prefix
 * both versions the format (a hypothetical `chall_v2` can migrate the
 * envelope without breaking existing verifiers) and lets a caller
 * cheaply refuse a non-challenge token before ever running the HMAC.
 *
 * HMAC covers `chall_v1.<b64u payload>` — the same string the caller
 * received minus the trailing tag. Any change to prefix, version, or
 * payload invalidates the signature.
 */

import { createHmac, randomBytes } from 'node:crypto';
import * as b64u from '@exortek/shared/base64url';
import { isObject, isString } from '@exortek/shared/predicates';
import { timingSafeEqual } from '@exortek/shared/timing-safe';

export const PREFIX = 'chall_v1';
const HMAC_ALG = 'sha256';

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
 * @returns {string}
 */
export function sign(payload, secret) {
  const body = `${PREFIX}.${b64u.encodeJson(payload)}`;
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
 * @returns {{ payload: object } | { reason: 'malformed' | 'bad_signature' }}
 */
export function decode(token, secret) {
  if (!isString(token) || token.length === 0) {
    return { reason: 'malformed' };
  }
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== PREFIX) {
    return { reason: 'malformed' };
  }
  const [, encodedPayload, encodedTag] = parts;
  let tag;
  try {
    tag = b64u.decode(encodedTag);
  } catch {
    return { reason: 'malformed' };
  }
  const expected = createHmac(HMAC_ALG, secret).update(`${PREFIX}.${encodedPayload}`).digest();
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
