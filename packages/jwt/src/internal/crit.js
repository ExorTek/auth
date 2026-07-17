/**
 * `crit` header validation. Scaffold stub; copied from `@exortek/jws`
 * in the utility-layer commit. JWT rarely uses `crit` in practice, but
 * we honour the JWS spec for tokens that carry it.
 */

import { JwtError, ErrorCode } from './errors.js';

export const KNOWN_CRIT = Object.freeze(new Set([]));

/** @param {unknown} _crit @param {Record<string, unknown>} _protectedHeader */
export function assertSignSide(_crit, _protectedHeader) {
  throw new JwtError(ErrorCode.INVALID_HEADER, 'crit.assertSignSide: not implemented');
}

/**
 * @param {unknown} _crit
 * @param {Record<string, unknown>} _protectedHeader
 * @param {Iterable<string>} [_extraKnown]
 */
export function assertVerifySide(_crit, _protectedHeader, _extraKnown) {
  throw new JwtError(ErrorCode.CRIT_UNSUPPORTED, 'crit.assertVerifySide: not implemented');
}
