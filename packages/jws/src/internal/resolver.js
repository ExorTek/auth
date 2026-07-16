/**
 * Verify-side key resolver — turn the polymorphic `key` argument into a
 * concrete `KeyObject`.
 *
 * Supported input shapes:
 *
 *   | Input                          | Behaviour                                                    |
 *   | ------------------------------ | ------------------------------------------------------------ |
 *   | `KeyObject`                    | Normalise and use directly                                   |
 *   | `Buffer` / `Uint8Array`        | HMAC secret only — non-HS* algs raise `INVALID_KEY`          |
 *   | JWK object (`{ kty, ... }`)    | Normalise through `keys.normalizeKey`                        |
 *   | JWK array                      | Match the token's `kid`; single-key array bypasses the match |
 *   | `async (header) => key`        | Await, then normalise the return value                       |
 */

import { KeyObject } from 'node:crypto';

import { JwsError, ErrorCode } from './errors.js';
import { normalizeKey } from './keys.js';

/**
 * @typedef {import('node:crypto').KeyObject} KeyObj
 * @typedef {import('./keys.js').KeyInput} KeyInput
 * @typedef {(header: Record<string, unknown>) => KeyInput | Promise<KeyInput>} KeyResolverFn
 */

/**
 * @param {KeyInput | KeyInput[] | KeyResolverFn} keyish
 * @param {Record<string, unknown>} header
 * @param {string} alg
 * @returns {Promise<KeyObj>}
 */
export async function resolveKey(keyish, header, alg) {
  if (typeof keyish === 'function') {
    const resolved = await keyish(header);
    return normalizeKey(resolved, alg, 'verify');
  }

  if (Array.isArray(keyish)) {
    if (keyish.length === 0) {
      throw new JwsError(
        ErrorCode.KEY_NOT_FOUND,
        'resolveKey: an empty key array was supplied. Pass at least one JWK / KeyObject or use a resolver function.',
      );
    }
    const kid = header.kid;
    if (kid !== undefined) {
      for (const candidate of keyish) {
        if (_kidMatches(candidate, kid)) {
          return normalizeKey(candidate, alg, 'verify');
        }
      }
      throw new JwsError(
        ErrorCode.KEY_NOT_FOUND,
        `resolveKey: no key with kid=${JSON.stringify(kid)} found in the supplied key set (checked ${keyish.length} candidate${keyish.length === 1 ? '' : 's'}).`,
      );
    }
    if (keyish.length === 1) {
      return normalizeKey(keyish[0], alg, 'verify');
    }
    throw new JwsError(
      ErrorCode.KEY_NOT_FOUND,
      'resolveKey: the token has no `kid` header but multiple keys were supplied — pass a resolver function or ensure the token carries a `kid`.',
    );
  }

  return normalizeKey(keyish, alg, 'verify');
}

/**
 * @param {unknown} candidate
 * @param {unknown} kid
 */
function _kidMatches(candidate, kid) {
  if (candidate instanceof KeyObject) {
    return false;
  } // KeyObjects carry no metadata
  if (candidate == null || typeof candidate !== 'object') {
    return false;
  }
  return /** @type {Record<string, unknown>} */ (candidate).kid === kid;
}
