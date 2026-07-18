/**
 * Duration parsing for rate-limit windows — adapter over the shared
 * parser. Bare numbers are a positive integer of **milliseconds**;
 * duration strings resolve through `@exortek/shared/duration`; every
 * result must be at least 1ms.
 */

import { parseDuration as sharedParseDuration } from '@exortek/shared/duration';
import { SecurityError, ErrorCode } from '../internal/errors.js';

/**
 * Parse a duration into milliseconds.
 *
 * Accepts:
 *   - Number → treated as milliseconds (must be positive integer)
 *   - String  → '500ms', '30s', '15m', '1h', '7d', '2w' (case-insensitive)
 *
 * Rejects zero, negatives, non-finite, unknown suffixes, and empty strings.
 *
 * @param {string | number} input
 * @param {string} [field='window'] — field name used in error messages
 * @returns {number} milliseconds
 */
export function parseDuration(input, field = 'window') {
  if (typeof input === 'number') {
    if (!Number.isFinite(input) || input <= 0 || !Number.isInteger(input)) {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        `${field} must be a positive integer of milliseconds or a duration string like '1m' / '15m' / '1h'; got ${input}`,
      );
    }
    return input;
  }
  if (typeof input !== 'string' || input.length === 0) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `${field} must be a duration string like '1m' / '15m' / '1h' / '7d' or a positive integer of milliseconds; got ${input === null ? 'null' : typeof input}`,
    );
  }
  let ms;
  try {
    ms = sharedParseDuration(input);
  } catch (err) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `${field} '${input}' is not a valid duration. Use '<number><unit>' where unit is ms | s | m | h | d | w (e.g. '500ms', '30s', '15m', '1h', '7d', '2w')`,
      { cause: err },
    );
  }
  if (ms <= 0) {
    throw new SecurityError(ErrorCode.INVALID_ARGUMENT, `${field} must resolve to at least 1ms; '${input}' → ${ms}ms`);
  }
  return ms;
}
