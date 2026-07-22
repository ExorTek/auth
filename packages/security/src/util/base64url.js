/**
 * base64url helpers (RFC 4648 §5) — thin adapters over the shared
 * codec, widened to accept plain strings on the encode side (CSRF
 * tokens and MAC tags are minted from strings in this package).
 */

import * as sb from '@exortek/shared/base64url';
import { isString } from '@exortek/shared/predicates';

/**
 * base64url encode — no padding, URL/cookie-safe.
 * @param {Buffer | Uint8Array | string} input
 * @returns {string}
 */
export function encodeBase64Url(input) {
  return isString(input) ? sb.encodeString(input) : sb.encode(input);
}

/**
 * base64url decode. Throws on invalid characters and non-canonical
 * encodings (strict — everything this package mints is canonical).
 * @param {string} input
 * @returns {Buffer}
 */
export function decodeBase64Url(input) {
  if (!isString(input)) {
    throw new TypeError('base64url input must be a string');
  }
  return sb.decode(input);
}
