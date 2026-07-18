/**
 * Duration parsing for session TTLs — adapter over the shared parser
 * that preserves this package's conventions: bare numbers are a
 * positive integer of **seconds** (backwards-compatible with the
 * `seal` API's TTL argument), duration strings resolve through
 * `@exortek/shared/duration`, and every result must be a positive
 * number of milliseconds.
 */

import { parseDuration as sharedParseDuration } from '@exortek/shared/duration';
import { SessionError, ErrorCode } from '../errors.js';

/**
 * Parse a duration to milliseconds. Accepts:
 *   - A positive integer number of seconds.
 *   - A duration string with a unit suffix: `'500ms'`, `'30s'`,
 *     `'15m'`, `'1h'`, `'7d'`, `'2w'`.
 *
 * @param {string | number} input
 * @param {string} name       Field label for the error message.
 * @returns {number}          Duration in milliseconds.
 */
export function parseDuration(input, name = 'duration') {
  if (typeof input === 'number') {
    if (!Number.isFinite(input) || input <= 0 || !Number.isInteger(input)) {
      throw new SessionError(
        ErrorCode.INVALID_ARGUMENT,
        `${name}: numeric duration must be a positive integer of seconds; got ${input}`,
      );
    }
    return input * 1000;
  }
  if (typeof input === 'string') {
    let ms;
    try {
      ms = sharedParseDuration(input);
    } catch (err) {
      throw new SessionError(
        ErrorCode.INVALID_ARGUMENT,
        `${name}: duration string ${JSON.stringify(input)} does not parse — use '<number><ms|s|m|h|d|w>'`,
        { cause: err },
      );
    }
    if (ms <= 0) {
      throw new SessionError(ErrorCode.INVALID_ARGUMENT, `${name}: duration must be positive; got ${input}`);
    }
    return ms;
  }
  throw new SessionError(
    ErrorCode.INVALID_ARGUMENT,
    `${name}: must be a positive integer of seconds or a duration string (got ${typeof input})`,
  );
}
