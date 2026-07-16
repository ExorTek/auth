/**
 * Algorithm registry — alg identifier → { hash, keyType, sign, verify }.
 * Scaffold stub; the real table lands in the "internal utility layer"
 * commit alongside `ecdsa.js` (which converts between Node's ASN.1
 * signature form and JWS raw R‖S).
 *
 * Notes carried over from the plan:
 *   - `none` is **not** an entry here. Lookups for it produce
 *     {@link ErrorCode.UNSUPPORTED_ALGORITHM}; the caller in `sign.js` /
 *     `verify.js` has a dedicated {@link ErrorCode.ALGORITHM_NONE_FORBIDDEN}
 *     path so the user sees the actionable message.
 *   - Every ES* alg must run through `ecdsa.rawToDer` on verify and
 *     `ecdsa.derToRaw` on sign.
 */

import { JwsError, ErrorCode } from './errors.js';

/**
 * Look up an algorithm's descriptor. Not implemented — placeholder.
 *
 * @param {string} alg
 */
export function lookup(alg) {
  throw new JwsError(
    ErrorCode.UNSUPPORTED_ALGORITHM,
    `algorithms.lookup: not implemented (asked for ${JSON.stringify(alg)})`,
  );
}

/**
 * Supported algorithm identifiers — the accept-list for both sign and
 * verify. Populated by the utility-layer commit.
 */
export const SUPPORTED = Object.freeze([]);
