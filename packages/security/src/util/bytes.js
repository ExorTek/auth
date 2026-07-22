import { randomBuffer } from '@exortek/shared/random';
import { timingSafeEqual as sharedTimingSafeEqual } from '@exortek/shared/timing-safe';
import { isString } from '@exortek/shared/predicates';

/**
 * Cryptographically secure random bytes.
 * @param {number} size
 * @returns {Buffer}
 */
export function randomBytes(size) {
  return randomBuffer(size);
}

/**
 * Constant-time buffer comparison. Returns false when lengths differ instead
 * of throwing (unlike `crypto.timingSafeEqual`), so it's safe on untrusted
 * inputs without leaking length via the exception path. Accepts strings for
 * caller convenience (UTF-8 bytes are compared).
 * @param {Buffer | Uint8Array | string} a
 * @param {Buffer | Uint8Array | string} b
 * @returns {boolean}
 */
export function timingSafeEqual(a, b) {
  const ba = isString(a) ? Buffer.from(a) : a;
  const bb = isString(b) ? Buffer.from(b) : b;
  return sharedTimingSafeEqual(ba, bb);
}
