/**
 * Length-safe `timingSafeEqual`.
 *
 * `crypto.timingSafeEqual` throws when its two arguments have
 * different lengths — the exception path is itself a side channel
 * that leaks "lengths differ" to a timing attacker even when the
 * caller catches the throw. This wrapper closes that channel by
 * always running a `timingSafeEqual` (against the shorter buffer
 * padded to itself) and returning `false` on length mismatch, so the
 * caller sees a boolean either way and total runtime does not
 * short-circuit on length alone.
 */

import { timingSafeEqual as nodeTimingSafeEqual } from 'node:crypto';

/**
 * @param {Buffer | Uint8Array} a
 * @param {Buffer | Uint8Array} b
 * @returns {boolean}
 */
export function timingSafeEqual(a, b) {
  const aBuf = Buffer.isBuffer(a) ? a : Buffer.from(a.buffer, a.byteOffset, a.byteLength);
  const bBuf = Buffer.isBuffer(b) ? b : Buffer.from(b.buffer, b.byteOffset, b.byteLength);
  if (aBuf.length !== bBuf.length) {
    // Burn a comparison so total time doesn't short-circuit on the
    // length gate — the attacker can't distinguish "length mismatch"
    // from "content mismatch" by observed runtime.
    nodeTimingSafeEqual(aBuf, aBuf);
    return false;
  }
  return nodeTimingSafeEqual(aBuf, bBuf);
}
