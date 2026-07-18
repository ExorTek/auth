import { assertObject, assertPositiveInt } from '@exortek/shared/asserts';
import { numeric } from './numeric.js';

/**
 * Check whether `digits` is a "weak" PIN — i.e., trivially guessable.
 *
 * Rejects:
 *   • all identical digits: `0000`, `1111`, …, `9999`
 *   • ascending runs (wraps `9 → 0`): `1234`, `5678`, `9012`, …
 *   • descending runs (wraps `0 → 9`): `4321`, `9876`, `1098`, …
 *
 * Weakness only makes sense for length ≥ 3; shorter inputs return `false`
 * (nothing to pattern-check).
 *
 * @private
 * @param {string} digits
 * @returns {boolean}
 */
function _isWeak(digits) {
  if (digits.length < 3) {
    return false;
  }
  const d = new Array(digits.length);
  for (let i = 0; i < digits.length; i++) {
    d[i] = digits.charCodeAt(i) - 48; // '0' = 48
  }

  // All identical.
  let allSame = true;
  for (let i = 1; i < d.length; i++) {
    if (d[i] !== d[0]) {
      allSame = false;
      break;
    }
  }
  if (allSame) {
    return true;
  }

  // Strictly ascending (mod 10) or strictly descending (mod 10).
  let asc = true;
  let desc = true;
  for (let i = 1; i < d.length; i++) {
    if (d[i] !== (d[i - 1] + 1) % 10) {
      asc = false;
    }
    if (d[i] !== (d[i - 1] + 9) % 10) {
      desc = false;
    }
    if (!asc && !desc) {
      break;
    }
  }
  return asc || desc;
}

/**
 * @typedef {object} PinOptions
 * @property {boolean} [avoidWeak=true]  When `true` (default), trivially guessable
 *                                        PINs (`0000`, `1234`, `9876`, …) are
 *                                        rejected and resampled. Set `false` for
 *                                        an unfiltered uniform numeric string.
 */

/**
 * Cryptographically secure numeric PIN.
 *
 * Delegates to bias-free {@link numeric} sampling; by default filters out
 * "weak" PINs (all-same digit or strictly sequential) so a fresh sample is
 * drawn until the result is non-trivial. Rejection rate is < 1% for length ≥ 4,
 * so in practice at most one resample happens.
 *
 * The weak filter only takes effect for length ≥ 3 — shorter values (1 or 2
 * digits) have no meaningful "pattern" so they pass through as-is.
 *
 * @param {number}     length     Number of digits. Must be a positive integer.
 * @param {PinOptions} [options]
 * @returns {string}              Random PIN of length `length`.
 * @throws {CryptoError}          With code `INVALID_ARGUMENT` if `length` is not a
 *                                positive integer or `options` is not an object.
 *
 * @example
 * pin(4)                          // '3729' — never '0000', '1111', '1234', …
 * pin(6)                          // '294816'
 * pin(4, { avoidWeak: false })    // unfiltered uniform numeric
 */
export function pin(length, options) {
  assertPositiveInt(length, 'pin length');
  if (options !== undefined) {
    assertObject(options, 'pin options');
  }
  const avoidWeak = options?.avoidWeak ?? true;

  if (!avoidWeak) {
    return numeric(length);
  }
  // Rejection rate ceiling: for length 4 it's 30/10000 = 0.3%.
  // In practice a single resample suffices; cap loop for safety.
  for (let attempt = 0; attempt < 32; attempt++) {
    const candidate = numeric(length);
    if (!_isWeak(candidate)) {
      return candidate;
    }
  }
  // Unreachable for any reasonable length; a safety net for pathological RNG.
  return numeric(length);
}
