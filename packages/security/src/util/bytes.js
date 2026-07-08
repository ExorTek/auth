import { randomBytes as _randomBytes, timingSafeEqual as _timingSafeEqual } from 'node:crypto';

/**
 * Cryptographically secure random bytes.
 * @param {number} size
 * @returns {Buffer}
 */
export function randomBytes(size) {
  return _randomBytes(size);
}

/**
 * Constant-time buffer comparison. Returns false when lengths differ instead
 * of throwing (unlike `crypto.timingSafeEqual`), so it's safe on untrusted
 * inputs without leaking length via the exception path.
 * @param {Buffer | Uint8Array | string} a
 * @param {Buffer | Uint8Array | string} b
 * @returns {boolean}
 */
export function timingSafeEqual(a, b) {
  const ba = typeof a === 'string' ? Buffer.from(a) : Buffer.from(a.buffer, a.byteOffset, a.byteLength);
  const bb = typeof b === 'string' ? Buffer.from(b) : Buffer.from(b.buffer, b.byteOffset, b.byteLength);
  if (ba.length !== bb.length) {
    // Still burn ~one comparison worth of time so callers can't distinguish
    // "wrong length" from "wrong value" via timing.
    _timingSafeEqual(ba, ba);
    return false;
  }
  return _timingSafeEqual(ba, bb);
}
