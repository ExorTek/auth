import { isString } from '@exortek/shared/predicates';

import { invalidArgument } from './guards.js';

const MIN_SECRET_BYTES = 32;

/**
 * Session and trusted-device cookies are sealed under this secret; an
 * empty or short one makes them forgeable. Fail at configuration time
 * rather than at the first seal.
 *
 * @param {string | Uint8Array} secret
 * @param {string} name
 */
export function assertSecretLength(secret, name) {
  const length = isString(secret) ? Buffer.byteLength(secret, 'utf8') : secret.length;
  if (length < MIN_SECRET_BYTES) {
    throw invalidArgument(`${name} entries must be at least ${MIN_SECRET_BYTES} bytes; got ${length}`);
  }
}
