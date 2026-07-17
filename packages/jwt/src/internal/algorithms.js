/**
 * Algorithm registry — alg identifier → { hash, keyType, sign, verify }.
 * Scaffold stub. Real table lands in the internal-utility-layer commit,
 * copied verbatim from `@exortek/jws` (HS/RS/PS/ES/EdDSA + secp256k1;
 * `none` deliberately not in the table).
 */

import { JwtError, ErrorCode } from './errors.js';

/**
 * @param {string} alg
 */
export function lookup(alg) {
  throw new JwtError(
    ErrorCode.UNSUPPORTED_ALGORITHM,
    `algorithms.lookup: not implemented (asked for ${JSON.stringify(alg)})`,
  );
}

/** Supported algorithm identifiers. Populated by the utility-layer commit. */
export const SUPPORTED = Object.freeze([]);
