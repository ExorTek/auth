/**
 * Key material normaliser — turn JWK objects, `KeyObject`s, and
 * `Buffer`/`Uint8Array` HMAC secrets into a shape the algorithms table
 * can use.
 *
 * Scaffold stub; implementation lands in the utility-layer commit.
 */

import { JwsError, ErrorCode } from './errors.js';

/**
 * @typedef {import('node:crypto').KeyObject} KeyObject
 * @typedef {KeyObject | Buffer | Uint8Array | Record<string, unknown>} KeyInput
 */

/**
 * Normalise a caller-supplied key into a `KeyObject`. Rejects mismatched
 * `kty` / algorithm pairings so alg-confusion attacks surface here.
 *
 * @param {KeyInput} _key
 * @param {string} _alg      the JWS algorithm identifier
 * @param {'sign' | 'verify'} _direction
 * @returns {Promise<KeyObject>}
 */
export async function normalizeKey(_key, _alg, _direction) {
  throw new JwsError(ErrorCode.INVALID_KEY, 'keys.normalizeKey: not implemented');
}
