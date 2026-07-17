/**
 * `crit` header validation (RFC 7515 §4.1.11). Standalone per package
 * policy — verbatim copy of `@exortek/jws`. JWT rarely uses `crit` in
 * practice, but the JWS spec still applies to any token that carries
 * one.
 */

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
  if (crit === undefined) {
    return;
  }
  _shapeChecks(crit);
  for (const name of /** @type {string[]} */ (crit)) {
    if (!(name in protectedHeader)) {
      throw new JwtError(
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
      throw new JwtError(
        ErrorCode.CRIT_UNSUPPORTED,
        `crit lists ${JSON.stringify(name)} — this verifier does not understand it. Add the name to knownCriticalHeaders if the caller is prepared to process it.`,
      );
    }
    if (!(name in protectedHeader)) {
      throw new JwtError(
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
    throw new JwtError(ErrorCode.INVALID_HEADER, 'crit must be a JSON array of strings');
  }
  if (crit.length === 0) {
    throw new JwtError(ErrorCode.INVALID_HEADER, 'crit must not be an empty array (RFC 7515 §4.1.11)');
  }
  const seen = new Set();
  for (const name of crit) {
    if (typeof name !== 'string' || name.length === 0) {
      throw new JwtError(ErrorCode.INVALID_HEADER, `crit contains a non-string entry ${JSON.stringify(name)}`);
    }
    if (name === 'crit') {
      throw new JwtError(ErrorCode.INVALID_HEADER, 'crit must not list itself (RFC 7515 §4.1.11)');
    }
    if (seen.has(name)) {
      throw new JwtError(ErrorCode.INVALID_HEADER, `crit contains duplicate entry ${JSON.stringify(name)}`);
    }
    seen.add(name);
  }
}
