/**
 * Verify-side key resolver — turn the polymorphic `key` argument into a
 * concrete `KeyObject`, shared by the jws / jwt verify surfaces.
 *
 * Supported input shapes:
 *
 *   | Input                          | Behaviour                                                    |
 *   | ------------------------------ | ------------------------------------------------------------ |
 *   | `KeyObject`                    | Normalise and use directly                                   |
 *   | `Buffer` / `Uint8Array`        | HMAC secret only — non-HS* algs raise via `normalize`        |
 *   | JWK object (`{ kty, ... }`)    | Normalise through the caller's `normalize`                   |
 *   | JWK array                      | Match the token's `kid`; single-key array bypasses the match |
 *   | `async (header) => key`        | Await, then normalise the return value                       |
 *
 * The caller supplies `normalize(keyInput, alg, use)` — the
 * package-specific coercion that already throws its own typed errors;
 * those propagate untouched. Missing-key failures raised *here* carry a
 * `keyNotFound: true` marker so the consuming package can wrap them
 * into its `KEY_NOT_FOUND` typed error at the surface boundary.
 */

import { KeyObject } from 'node:crypto';

/**
 * @param {string} message
 * @returns {Error & { keyNotFound: true }}
 */
function _missing(message) {
  return Object.assign(new Error(message), { keyNotFound: /** @type {const} */ (true) });
}

/**
 * @template K
 * @param {(keyInput: K, alg: string, use: 'verify') => import('node:crypto').KeyObject} normalize
 * @returns {(keyish: K | K[] | ((header: Record<string, unknown>) => K | Promise<K>), header: Record<string, unknown>, alg: string) => Promise<import('node:crypto').KeyObject>}
 */
export function createKeyResolver(normalize) {
  return async function resolveKey(keyish, header, alg) {
    if (typeof keyish === 'function') {
      const resolved = await /** @type {(h: Record<string, unknown>) => K | Promise<K>} */ (keyish)(header);
      return normalize(resolved, alg, 'verify');
    }

    if (Array.isArray(keyish)) {
      if (keyish.length === 0) {
        throw _missing(
          'resolveKey: an empty key array was supplied. Pass at least one JWK / KeyObject or use a resolver function.',
        );
      }
      const kid = header.kid;
      if (kid !== undefined) {
        for (const candidate of keyish) {
          if (_kidMatches(candidate, kid)) {
            return normalize(candidate, alg, 'verify');
          }
        }
        throw _missing(
          `resolveKey: no key with kid=${JSON.stringify(kid)} found in the supplied key set (checked ${keyish.length} candidate${keyish.length === 1 ? '' : 's'}).`,
        );
      }
      if (keyish.length === 1) {
        return normalize(keyish[0], alg, 'verify');
      }
      throw _missing(
        'resolveKey: the token has no `kid` header but multiple keys were supplied — pass a resolver function or ensure the token carries a `kid`.',
      );
    }

    return normalize(keyish, alg, 'verify');
  };
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
