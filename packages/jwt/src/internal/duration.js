/**
 * Human-duration parser for JWT `expiresIn` / `notBefore` /
 * `clockTolerance` / `maxAge`. Returns **seconds** (integer) — matches
 * RFC 7519's NumericDate for `exp` / `nbf` / `iat` arithmetic.
 *
 * Bare numbers pass through unchanged (already in seconds). Bare
 * numeric strings (`'60'`) parse as seconds.
 *
 * Supported suffixes:
 *
 *   | Unit | Suffix    | Seconds |
 *   | ---- | --------- | ------- |
 *   | ms   | `ms`      | 1/1000  |
 *   | s    | `s` / `sec` / `second[s]` | 1        |
 *   | m    | `m` / `min` / `minute[s]` | 60       |
 *   | h    | `h` / `hr` / `hour[s]`    | 3600     |
 *   | d    | `d` / `day[s]`            | 86400    |
 *   | w    | `w` / `wk` / `week[s]`    | 604800   |
 *
 * The parser is deliberately strict — anything it doesn't understand
 * raises {@link ErrorCode.INVALID_ARGUMENT} instead of silently
 * defaulting.
 *
 * Cross-package note: `@exortek/session` and `@exortek/crypto` ship
 * duration parsers with the same unit alphabet (`ms|s|m|h|d|w`) but
 * they return **milliseconds** and accept a stricter grammar (no
 * long/plural forms, no fractional values, no whitespace). Every
 * short-form value accepted here is accepted there too; a long-form
 * value like `'15 minutes'` is jwt-only.
 */

import { JwtError, ErrorCode } from './errors.js';

const UNIT_SECONDS = Object.freeze({
  ms: 1 / 1000,
  s: 1,
  sec: 1,
  second: 1,
  seconds: 1,
  m: 60,
  min: 60,
  minute: 60,
  minutes: 60,
  h: 3600,
  hr: 3600,
  hour: 3600,
  hours: 3600,
  d: 86400,
  day: 86400,
  days: 86400,
  w: 604800,
  wk: 604800,
  week: 604800,
  weeks: 604800,
});

const DURATION_RE = /^\s*(-?\d+(?:\.\d+)?)\s*([a-z]+)?\s*$/i;

/**
 * @param {string | number} input
 * @returns {number} seconds (may be fractional if `ms` used)
 */
export function parseDuration(input) {
  if (typeof input === 'number') {
    if (!Number.isFinite(input)) {
      throw new JwtError(ErrorCode.INVALID_ARGUMENT, `parseDuration: numeric input must be finite; got ${input}`);
    }
    return input;
  }
  if (typeof input !== 'string') {
    throw new JwtError(ErrorCode.INVALID_ARGUMENT, `parseDuration: expected string or number; got ${typeof input}`);
  }

  const match = DURATION_RE.exec(input);
  if (!match) {
    throw new JwtError(
      ErrorCode.INVALID_ARGUMENT,
      `parseDuration: could not parse ${JSON.stringify(input)}. Examples: '15m', '2h', '7d', '500ms', '30s', or a bare number of seconds.`,
    );
  }
  const value = Number(match[1]);
  const unit = (match[2] || 's').toLowerCase();
  const multiplier = UNIT_SECONDS[/** @type {keyof typeof UNIT_SECONDS} */ (unit)];
  if (multiplier === undefined) {
    throw new JwtError(
      ErrorCode.INVALID_ARGUMENT,
      `parseDuration: unknown time unit ${JSON.stringify(unit)}. Supported: ms, s, m, h, d, w (and full/plural forms).`,
    );
  }
  return value * multiplier;
}
