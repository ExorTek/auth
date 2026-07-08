import { SecurityError, ErrorCode } from '../internal/errors.js';

const UNITS = {
  ms: 1,
  s: 1000,
  m: 60 * 1000,
  h: 60 * 60 * 1000,
  d: 24 * 60 * 60 * 1000,
  w: 7 * 24 * 60 * 60 * 1000,
};

const PATTERN = /^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)\s*$/i;

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
  const match = PATTERN.exec(input);
  if (!match) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `${field} '${input}' is not a valid duration. Use '<number><unit>' where unit is ms | s | m | h | d | w (e.g. '500ms', '30s', '15m', '1h', '7d', '2w')`,
    );
  }
  const value = Number(match[1]);
  const unit = match[2].toLowerCase();
  const ms = Math.round(value * UNITS[unit]);
  if (ms <= 0) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `${field} must resolve to at least 1ms; '${input}' → ${ms}ms`,
    );
  }
  return ms;
}
