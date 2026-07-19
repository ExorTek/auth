/**
 * `crypto.randomBytes` re-exported as `randomBuffer(size)`. Kept here
 * so consumer packages can reach for a single shared name instead of
 * inventing wrappers around the same primitive.
 */

import { randomBytes } from 'node:crypto';

/**
 * @param {number} size  positive integer number of bytes
 * @returns {Buffer}
 * @throws {Error} on non-integer / negative / NaN / non-number `size`
 *                 — surfaces earlier than Node's raw `RangeError` and
 *                 with a consistent message.
 */
export function randomBuffer(size) {
  if (typeof size !== 'number' || !Number.isSafeInteger(size) || size < 0) {
    throw new Error(`randomBuffer.size must be a non-negative safe integer; got ${size}`);
  }
  return randomBytes(size);
}
