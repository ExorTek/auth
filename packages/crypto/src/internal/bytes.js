/**
 * Coerce string / Buffer / Uint8Array into a Buffer. Wraps
 * `@exortek/shared/bytes` so failures surface as
 * `CryptoError(INVALID_ARGUMENT)` via the bound `invalidArgument`.
 */

import * as sb from '@exortek/shared/bytes';
import { invalidArgument } from './guards.js';

/**
 * @param {unknown} value
 * @param {string}  name
 * @returns {Buffer}
 */
export function toBuffer(value, name) {
  try {
    return sb.toBuffer(value, name);
  } catch (err) {
    throw invalidArgument(err instanceof Error ? err.message : String(err), { cause: err });
  }
}

/**
 * @param {unknown} value
 * @param {string}  name
 * @param {'hex' | 'base64' | 'base64url'} encoding
 * @returns {Buffer}
 */
export function toBufferWithEncoding(value, name, encoding) {
  try {
    return sb.toBufferWithEncoding(value, name, encoding);
  } catch (err) {
    throw invalidArgument(err instanceof Error ? err.message : String(err), { cause: err });
  }
}
