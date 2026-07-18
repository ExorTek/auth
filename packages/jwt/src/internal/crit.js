/**
 * `crit` header validation (RFC 7515 §4.1.11) — adapter over the
 * shared implementation. JWT rarely uses `crit` in practice, but the
 * JWS spec still applies to any token that carries one.
 *
 * On sign: every name in `crit` must be present as a header parameter,
 * `crit` cannot list itself, and the array must be non-empty.
 *
 * On verify: every name in `crit` must be either a header parameter
 * this library understands out of the box or explicitly opted-in via
 * the `knownCriticalHeaders` verify option. Unknown critical parameters
 * raise {@link ErrorCode.CRIT_UNSUPPORTED}.
 */

import * as sc from '@exortek/shared/crit';
import { JwtError, ErrorCode } from './errors.js';

/**
 * Critical header names this package understands without an explicit
 * opt-in from the verifier. JWT does not use `b64` (RFC 7797) — that
 * extension is JWS-only — so this set is empty. Add opt-in names via
 * the `knownCriticalHeaders` verify option.
 */
export const KNOWN_CRIT = Object.freeze(new Set([]));

/**
 * @param {unknown} crit
 * @param {Record<string, unknown>} protectedHeader
 */
export function assertSignSide(crit, protectedHeader) {
  try {
    sc.assertSignSide(crit, protectedHeader);
  } catch (err) {
    throw new JwtError(ErrorCode.INVALID_HEADER, err instanceof Error ? err.message : String(err));
  }
}

/**
 * @param {unknown} crit
 * @param {Record<string, unknown>} protectedHeader
 * @param {Iterable<string>} [extraKnown]
 */
export function assertVerifySide(crit, protectedHeader, extraKnown) {
  try {
    sc.assertVerifySide(crit, protectedHeader, KNOWN_CRIT, extraKnown);
  } catch (err) {
    const unknownCrit = err !== null && typeof err === 'object' && 'critName' in err;
    throw new JwtError(
      unknownCrit ? ErrorCode.CRIT_UNSUPPORTED : ErrorCode.INVALID_HEADER,
      err instanceof Error ? err.message : String(err),
    );
  }
}
