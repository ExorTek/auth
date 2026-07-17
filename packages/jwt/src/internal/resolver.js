/**
 * Verify-side key resolver. Scaffold stub; copied from `@exortek/jws`
 * in the utility-layer commit. Same polymorphism: single key, JWK array
 * with kid dispatch, or `async (header) => key` resolver function.
 */

import { JwtError, ErrorCode } from './errors.js';

/**
 * @typedef {import('./keys.js').KeyInput} KeyInput
 * @typedef {(header: Record<string, unknown>) => KeyInput | Promise<KeyInput>} KeyResolverFn
 */

/**
 * @param {KeyInput | KeyInput[] | KeyResolverFn} _keyish
 * @param {Record<string, unknown>} _header
 * @param {string} _alg
 * @returns {Promise<import('node:crypto').KeyObject>}
 */
export async function resolveKey(_keyish, _header, _alg) {
  throw new JwtError(ErrorCode.KEY_NOT_FOUND, 'resolver.resolveKey: not implemented');
}
