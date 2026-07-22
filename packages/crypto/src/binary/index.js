import { timingSafeEqual } from '@exortek/shared/timing-safe';
import { toBuffer } from '../internal/bytes.js';
import { assertBytes, invalidArgument } from '../internal/guards.js';

/**
 * @typedef {string | Buffer | Uint8Array} BytesInput
 */

/**
 * Concatenate any number of byte inputs (strings interpreted as UTF-8) into
 * a single `Buffer`. Thin wrapper over `Buffer.concat` that also accepts
 * string arguments and validates every input.
 *
 * @param {...BytesInput} parts
 * @returns {Buffer}
 * @throws {CryptoError} `INVALID_ARGUMENT` if any part is not a string or Buffer.
 *
 * @example
 * concat('user:', userId, ':', Buffer.from([0x00]))
 */
export function concat(...parts) {
  const bufs = parts.map((p, i) => toBuffer(p, `parts[${i}]`));
  return Buffer.concat(bufs);
}

/**
 * XOR two equal-length byte buffers. Used in one-time-pad style masks,
 * key mixing, HKDF-adjacent constructions.
 *
 * @param {BytesInput} a
 * @param {BytesInput} b
 * @returns {Buffer}
 * @throws {CryptoError} `INVALID_ARGUMENT` if inputs are invalid types or
 *                       lengths differ.
 *
 * @example
 * xor(mask, plaintext)  // symmetric — xor again with same mask recovers plaintext
 */
export function xor(a, b) {
  const bufA = toBuffer(a, 'a');
  const bufB = toBuffer(b, 'b');
  if (bufA.length !== bufB.length) {
    throw invalidArgument(`xor operands must have equal length; got a=${bufA.length} bytes, b=${bufB.length} bytes`);
  }
  const out = Buffer.allocUnsafe(bufA.length);
  for (let i = 0; i < bufA.length; i++) {
    out[i] = bufA[i] ^ bufB[i];
  }
  return out;
}

/**
 * Best-effort zero-fill a Buffer in-place.
 *
 * Important: Node.js / V8 does not guarantee that the wiped bytes are
 * scrubbed from process memory — the garbage collector may have already
 * copied them, `Buffer.slice()` returns views that share backing storage,
 * and OS memory pages can be paged to disk. Use this as a *hint* for key
 * hygiene, not a hard guarantee.
 *
 * @param {Buffer | Uint8Array} buf
 * @returns {void}
 * @throws {CryptoError} `INVALID_ARGUMENT` if `buf` is not a Buffer/Uint8Array.
 *
 * @example
 * const key = await pbkdf2(pw, { salt })
 * // ... use key ...
 * wipe(key)  // hint the GC / signal intent that this is spent
 */
export function wipe(buf) {
  assertBytes(buf, 'wipe target', { hint: 'strings are immutable — nothing to wipe' });
  buf.fill(0);
}

/**
 * Timing-safe equality check for two byte inputs. Delegates to
 * `crypto.timingSafeEqual`. When lengths differ returns `false` immediately —
 * see `hash.compare` for the same helper on the hash namespace.
 *
 * @param {BytesInput} a
 * @param {BytesInput} b
 * @returns {boolean}
 * @throws {CryptoError} `INVALID_ARGUMENT` if either input is invalid.
 *
 * @example
 * if (!equal(receivedSig, expectedSig)) throw new Error('bad signature')
 */
export function equal(a, b) {
  return timingSafeEqual(toBuffer(a, 'a'), toBuffer(b, 'b'));
}
