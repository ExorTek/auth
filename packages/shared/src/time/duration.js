/**
 * Human-duration parser — the single source of truth across the
 * `@exortek/*` stack.
 *
 * Accepts:
 *   - `number` (positive integer) → interpreted as **seconds** to
 *     match the repository-wide convention (`expiresIn: 900` means
 *     15 minutes everywhere).
 *   - `string` with a unit suffix — long / plural / short forms all
 *     work. Whitespace and fractional values tolerated on the input
 *     side; the output is always integer milliseconds after rounding.
 *
 * Returns: **milliseconds** — Node's native time unit. Callers that
 * need integer seconds (e.g. JWT `exp` claims per RFC 7519 NumericDate)
 * divide by 1000 at their surface boundary.
 *
 * Supported units:
 *
 *   | Unit | Short              | Long / plural                      |
 *   | ---- | ------------------ | ---------------------------------- |
 *   | ms   | `ms`               | `millisecond`, `milliseconds`      |
 *   | s    | `s`, `sec`         | `second`, `seconds`                |
 *   | m    | `m`, `min`         | `minute`, `minutes`                |
 *   | h    | `h`, `hr`          | `hour`, `hours`                    |
 *   | d    | `d`                | `day`, `days`                      |
 *   | w    | `w`, `wk`          | `week`, `weeks`                    |
 *
 * Deliberately strict — anything the parser doesn't understand throws
 * instead of silently defaulting.
 */

const UNIT_MS = Object.freeze({
  ms: 1,
  millisecond: 1,
  milliseconds: 1,
  s: 1000,
  sec: 1000,
  second: 1000,
  seconds: 1000,
  m: 60_000,
  min: 60_000,
  minute: 60_000,
  minutes: 60_000,
  h: 3_600_000,
  hr: 3_600_000,
  hour: 3_600_000,
  hours: 3_600_000,
  d: 86_400_000,
  day: 86_400_000,
  days: 86_400_000,
  w: 604_800_000,
  wk: 604_800_000,
  week: 604_800_000,
  weeks: 604_800_000,
});

const DURATION_RE = /^\s*(-?\d+(?:\.\d+)?)\s*([a-z]+)?\s*$/i;

const SUPPORTED_UNITS = 'ms, s, m, h, d, w (and long/plural forms)';

/**
 * Parse a human duration to milliseconds.
 *
 * @param {string | number} input
 * @returns {number} milliseconds (integer)
 * @throws {Error} on malformed input
 *
 * @example
 *   parseDuration(900)        // → 900_000  (bare number = seconds)
 *   parseDuration('500ms')    // → 500
 *   parseDuration('15m')      // → 900_000
 *   parseDuration('2 hours')  // → 7_200_000
 *   parseDuration('7d')       // → 604_800_000
 */
export function parseDuration(input) {
  if (typeof input === 'number') {
    if (!Number.isFinite(input)) {
      throw new Error(`parseDuration: numeric input must be finite; got ${input}`);
    }
    // Repository convention: bare number is seconds, matching every
    // shipped package's public API (`expiresIn: 900` → 15 minutes).
    return Math.round(input * 1000);
  }
  if (typeof input !== 'string') {
    throw new TypeError(`parseDuration: expected string or number; got ${typeof input}`);
  }

  const match = DURATION_RE.exec(input);
  if (!match) {
    throw new Error(
      `parseDuration: could not parse ${JSON.stringify(input)}. Examples: 900 (seconds), '15m', '2h', '7d', '500ms', '30s'.`,
    );
  }
  const value = Number(match[1]);
  const unit = (match[2] || 's').toLowerCase();
  const multiplier = UNIT_MS[/** @type {keyof typeof UNIT_MS} */ (unit)];
  if (multiplier === undefined) {
    throw new Error(`parseDuration: unknown time unit ${JSON.stringify(unit)}. Supported: ${SUPPORTED_UNITS}.`);
  }
  return Math.round(value * multiplier);
}
