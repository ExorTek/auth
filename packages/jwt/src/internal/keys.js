/**
 * Key material normaliser — accepts `KeyObject`, `Buffer` / `Uint8Array`
 * HMAC secrets, JWK objects, and **PEM strings / X.509 certificates**
 * (jwt-specific extension over the jws inheritance).
 *
 * Scaffold stub. The real implementation lands in the utility-layer
 * commit; it mirrors `@exortek/jws`'s `normalizeKey` plus a PEM header
 * branch that dispatches raw file contents.
 */

import { JwtError, ErrorCode } from './errors.js';

/**
 * @typedef {import('node:crypto').KeyObject | Buffer | Uint8Array | string | Record<string, unknown>} KeyInput
 */

/**
 * @param {KeyInput} _key
 * @param {string} _alg
 * @param {'sign' | 'verify'} _direction
 * @returns {Promise<import('node:crypto').KeyObject>}
 */
export async function normalizeKey(_key, _alg, _direction) {
  throw new JwtError(ErrorCode.INVALID_KEY, 'keys.normalizeKey: not implemented');
}
