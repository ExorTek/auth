/**
 * `crit` header validation (RFC 7515 §4.1.11).
 *
 * The set of critical-header names the verifier recognises out of the
 * box is package-specific — jws ships `b64` (RFC 7797), jwt has no
 * built-in known names because the JWT surface doesn't use `crit`
 * itself. Consumers pass their `known` set when calling
 * `assertVerifySide`.
 *
 * On sign: every name in `crit` must be present as a header parameter,
 * `crit` cannot list itself, and the array must be non-empty.
 *
 * On verify: every name in `crit` must be either in the caller's
 * `known` set or in `extraKnown` (the runtime opt-in via a verify
 * option). Unknown critical parameters throw — consumers wrap with a
 * `CRIT_UNSUPPORTED` typed error at their surface boundary.
 */

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
      throw new Error(`crit lists ${JSON.stringify(name)} but the protected header has no such member (RFC 7515 §4.1.11)`);
    }
  }
}

/**
 * @param {unknown} crit
 * @param {Record<string, unknown>} protectedHeader
 * @param {Iterable<string>} known             Names the caller ships as built-in support.
 * @param {Iterable<string>} [extraKnown]      Runtime opt-in via a verify option.
 */
export function assertVerifySide(crit, protectedHeader, known, extraKnown) {
  if (crit === undefined) {
    return;
  }
  _shapeChecks(crit);
  const merged = new Set([...(known || []), ...(extraKnown || [])]);
  for (const name of /** @type {string[]} */ (crit)) {
    if (!merged.has(name)) {
      throw Object.assign(
        new Error(
          `crit lists ${JSON.stringify(name)} — this verifier does not understand it. Add the name to knownCriticalHeaders if the caller is prepared to process it.`,
        ),
        { critName: name },
      );
    }
    if (!(name in protectedHeader)) {
      throw new Error(`crit lists ${JSON.stringify(name)} but the protected header has no such member (RFC 7515 §4.1.11)`);
    }
  }
}

/** @param {unknown} crit */
function _shapeChecks(crit) {
  if (!Array.isArray(crit)) {
    throw new Error('crit must be a JSON array of strings');
  }
  if (crit.length === 0) {
    throw new Error('crit must not be an empty array (RFC 7515 §4.1.11)');
  }
  const seen = new Set();
  for (const name of crit) {
    if (typeof name !== 'string' || name.length === 0) {
      throw new Error(`crit contains a non-string entry ${JSON.stringify(name)}`);
    }
    if (name === 'crit') {
      throw new Error('crit must not list itself (RFC 7515 §4.1.11)');
    }
    if (seen.has(name)) {
      throw new Error(`crit contains duplicate entry ${JSON.stringify(name)}`);
    }
    seen.add(name);
  }
}
