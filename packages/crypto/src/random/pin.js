import { assertObject, assertPositiveInt } from '../internal/validate.js';
import { numeric } from './numeric.js';

/**
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
 * @param {number}     length     Number of digits. Must be a positive integer.
 * @param {PinOptions} [options]
 * @returns {string}              Random PIN of length `length`.
 * @throws {CryptoError}          With code `INVALID_ARGUMENT` on invalid inputs.
 */
export function pin(length, options) {
  assertPositiveInt(length, 'length');
  if (options !== undefined) {
    assertObject(options, 'options');
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
