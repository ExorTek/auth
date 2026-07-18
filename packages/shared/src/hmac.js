/**
 * `node:crypto` `createHmac` wrapper with an encoding shortcut. Same
 * reduction as `hash()`:
 *
 *   createHmac('sha256', secret).update(data).digest('hex')
 *   →
 *   hmac('sha256', secret, data, 'hex')
 */

import { createHmac } from 'node:crypto';

/**
 * @param {string} algo                                    e.g. `'sha256'`, `'sha384'`, `'sha512'`
 * @param {string | Buffer | Uint8Array | import('node:crypto').KeyObject} secret
 * @param {string | Buffer | Uint8Array} data
 * @param {'hex' | 'base64' | 'base64url' | undefined} [encoding]  Omit for raw Buffer.
 * @returns {string | Buffer}
 */
export function hmac(algo, secret, data, encoding) {
  const h = createHmac(algo, secret).update(data);
  return encoding ? h.digest(encoding) : h.digest();
}
