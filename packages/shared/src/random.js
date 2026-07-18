/**
 * `crypto.randomBytes` re-exported as `randomBuffer(size)`. Kept here
 * so consumer packages can reach for a single shared name instead of
 * inventing wrappers around the same primitive.
 */

import { randomBytes } from 'node:crypto';

/**
 * @param {number} size  positive integer number of bytes
 * @returns {Buffer}
 */
export function randomBuffer(size) {
  return randomBytes(size);
}
