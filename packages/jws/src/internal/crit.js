/**
 * `crit` header validation (RFC 7515 §4.1.11).
 *
 * On sign: every name in `crit` must be present as a header parameter.
 * On verify: every name in `crit` must be either a header parameter
 * this library understands (`b64`) or explicitly opted-in via the
 * `knownCriticalHeaders` verify option.
 *
 * Scaffold stub; implementation lands in the utility-layer commit.
 */

import { JwsError, ErrorCode } from './errors.js';

/**
 * Critical header names this package recognises without an explicit
 * opt-in from the verifier. Populated by the utility-layer commit.
 */
export const KNOWN_CRIT = Object.freeze(new Set(['b64']));

/**
 * @param {string[] | undefined} _crit
 * @param {Record<string, unknown>} _protectedHeader
 */
export function assertSignSide(_crit, _protectedHeader) {
  throw new JwsError(ErrorCode.INVALID_HEADER, 'crit.assertSignSide: not implemented');
}

/**
 * @param {string[] | undefined} _crit
 * @param {Record<string, unknown>} _protectedHeader
 * @param {Iterable<string>} [_extraKnown]
 */
export function assertVerifySide(_crit, _protectedHeader, _extraKnown) {
  throw new JwsError(ErrorCode.CRIT_UNSUPPORTED, 'crit.assertVerifySide: not implemented');
}
