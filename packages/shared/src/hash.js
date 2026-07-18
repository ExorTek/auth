/**
 * `node:crypto` `createHash` wrapper with an encoding shortcut. Reduces
 * the boilerplate every consumer package was repeating:
 *
 *   createHash('sha256').update(data).digest('hex')
 *   →
 *   hash('sha256', data, 'hex')
 *
 * Accepts everything Node's `Hash.update()` accepts (string, Buffer,
 * Uint8Array). Returns a string in the requested encoding or a raw
 * Buffer when the encoding is omitted.
 */

import { createHash } from 'node:crypto';

/**
 * @param {string} algo                                    e.g. `'sha256'`, `'sha384'`, `'sha512'`
 * @param {string | Buffer | Uint8Array} data
 * @param {'hex' | 'base64' | 'base64url' | undefined} [encoding]  Omit for raw Buffer.
 * @returns {string | Buffer}
 */
export function hash(algo, data, encoding) {
  const h = createHash(algo).update(data);
  return encoding ? h.digest(encoding) : h.digest();
}
