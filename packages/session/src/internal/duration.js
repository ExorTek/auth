import { SessionError, ErrorCode } from '../errors.js';

const UNITS = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000, w: 604_800_000 };
const RE = /^(\d+)(ms|s|m|h|d|w)$/;

/**
 * Parse a duration to milliseconds. Accepts:
 *   - A positive integer number of seconds (backwards-compatible with the
 *     `seal` API's TTL argument).
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
    const m = RE.exec(input);
    if (!m) {
      throw new SessionError(
        ErrorCode.INVALID_ARGUMENT,
        `${name}: duration string ${JSON.stringify(input)} does not parse — use '<number><ms|s|m|h|d|w>'`,
      );
    }
    const n = Number(m[1]);
    if (n <= 0) {
      throw new SessionError(ErrorCode.INVALID_ARGUMENT, `${name}: duration must be positive; got ${input}`);
    }
    return n * UNITS[m[2]];
  }
  throw new SessionError(
    ErrorCode.INVALID_ARGUMENT,
    `${name}: must be a positive integer of seconds or a duration string (got ${typeof input})`,
  );
}
