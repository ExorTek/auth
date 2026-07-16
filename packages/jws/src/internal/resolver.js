/**
 * Verify-side key resolver — turn the polymorphic `key` argument into a
 * concrete `KeyObject` (or list of candidates for `kid` dispatch).
 *
 * Supported input shapes:
 *
 *   | Input                          | Behaviour                                                    |
 *   | ------------------------------ | ------------------------------------------------------------ |
 *   | `KeyObject`                    | Use directly                                                 |
 *   | `Buffer` / `Uint8Array`        | HMAC secret only — non-HS* algs raise `INVALID_KEY`          |
 *   | JWK object (`{ kty, ... }`)    | Normalise through `keys.normalizeKey`                        |
 *   | JWK array                      | Pick the one whose `kid` matches the token header            |
 *   | `async (header) => key`        | Await, then normalise the return value                       |
 *
 * Scaffold stub; implementation lands in the utility-layer commit.
 */

import { JwsError, ErrorCode } from './errors.js';

/**
 * @typedef {import('node:crypto').KeyObject} KeyObject
 * @typedef {import('./keys.js').KeyInput} KeyInput
 * @typedef {(header: Record<string, unknown>) => KeyInput | Promise<KeyInput>} KeyResolverFn
 */

/**
 * @param {KeyInput | KeyInput[] | KeyResolverFn} _keyish
 * @param {Record<string, unknown>} _protectedHeader
 * @param {string} _alg
 * @returns {Promise<KeyObject>}
 */
export async function resolveKey(_keyish, _protectedHeader, _alg) {
  throw new JwsError(ErrorCode.KEY_NOT_FOUND, 'resolver.resolveKey: not implemented');
}
