/**
 * `crit` header validation (RFC 7515 §4.1.11).
 *
 * On sign: every name in `crit` must be present as a header parameter,
 * `crit` cannot list itself, and the array must be non-empty.
 *
 * On verify: every name in `crit` must be either a header parameter
 * this library understands out of the box (currently just `b64`) or
 * explicitly opted-in via the `knownCriticalHeaders` verify option.
 * Unknown critical parameters raise {@link ErrorCode.CRIT_UNSUPPORTED}.
 */

import { JwsError, ErrorCode } from './errors.js';

/**
 * Critical header names this package recognises without an explicit
 * opt-in from the verifier.
 *   - `b64` (RFC 7797) — the unencoded-payload marker
 */
export const KNOWN_CRIT = Object.freeze(new Set(['b64']));

/**
 * @param {unknown} crit
 * @param {Record<string, unknown>} protectedHeader
 */
export function assertSignSide(crit, protectedHeader) {
  if (crit === undefined) {
    return;
  }
  _shapeChecks(crit);
  for (const name of /** @type {string[]} */ (crit)) {
    if (!(name in protectedHeader)) {
      throw new JwsError(
        ErrorCode.INVALID_HEADER,
        `crit lists ${JSON.stringify(name)} but the protected header has no such member (RFC 7515 §4.1.11)`,
      );
    }
  }
}

/**
 * @param {unknown} crit
 * @param {Record<string, unknown>} protectedHeader
 * @param {Iterable<string>} [extraKnown]
 */
export function assertVerifySide(crit, protectedHeader, extraKnown) {
  if (crit === undefined) {
    return;
  }
  _shapeChecks(crit);
  const known = new Set([...KNOWN_CRIT, ...(extraKnown || [])]);
  for (const name of /** @type {string[]} */ (crit)) {
    if (!known.has(name)) {
      throw new JwsError(
        ErrorCode.CRIT_UNSUPPORTED,
        `crit lists ${JSON.stringify(name)} — this verifier does not understand it. Add the name to knownCriticalHeaders if the caller is prepared to process it.`,
      );
    }
    if (!(name in protectedHeader)) {
      throw new JwsError(
        ErrorCode.INVALID_HEADER,
        `crit lists ${JSON.stringify(name)} but the protected header has no such member (RFC 7515 §4.1.11)`,
      );
    }
  }
}

/**
 * @param {unknown} crit
 */
function _shapeChecks(crit) {
  if (!Array.isArray(crit)) {
    throw new JwsError(ErrorCode.INVALID_HEADER, 'crit must be a JSON array of strings');
  }
  if (crit.length === 0) {
    throw new JwsError(ErrorCode.INVALID_HEADER, 'crit must not be an empty array (RFC 7515 §4.1.11)');
  }
  const seen = new Set();
  for (const name of crit) {
    if (typeof name !== 'string' || name.length === 0) {
      throw new JwsError(ErrorCode.INVALID_HEADER, `crit contains a non-string entry ${JSON.stringify(name)}`);
    }
    if (name === 'crit') {
      throw new JwsError(ErrorCode.INVALID_HEADER, 'crit must not list itself (RFC 7515 §4.1.11)');
    }
    if (seen.has(name)) {
      throw new JwsError(ErrorCode.INVALID_HEADER, `crit contains duplicate entry ${JSON.stringify(name)}`);
    }
    seen.add(name);
  }
}
