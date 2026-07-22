/**
 * Verify-side key resolver — adapter over the shared implementation.
 * `normalizeKey` (this package's coercion) throws typed `JwsError`s
 * that propagate untouched; missing-key failures raised by the shared
 * resolver are wrapped into {@link ErrorCode.KEY_NOT_FOUND}.
 */

import { createKeyResolver } from '@exortek/shared/key-resolver';
import { isObject } from '@exortek/shared/predicates';

import { JwsError, ErrorCode } from './errors.js';
import { normalizeKey } from './keys.js';

/**
 * @typedef {import('node:crypto').KeyObject} KeyObj
 * @typedef {import('./keys.js').KeyInput} KeyInput
 * @typedef {(header: Record<string, unknown>) => KeyInput | Promise<KeyInput>} KeyResolverFn
 */

const _resolveKey = createKeyResolver(normalizeKey);

/**
 * @param {KeyInput | KeyInput[] | KeyResolverFn} keyish
 * @param {Record<string, unknown>} header
 * @param {string} alg
 * @returns {Promise<KeyObj>}
 */
export async function resolveKey(keyish, header, alg) {
  try {
    return await _resolveKey(keyish, header, alg);
  } catch (err) {
    if (isObject(err) && 'keyNotFound' in err) {
      throw new JwsError(ErrorCode.KEY_NOT_FOUND, /** @type {Error} */ (err).message);
    }
    throw err;
  }
}
