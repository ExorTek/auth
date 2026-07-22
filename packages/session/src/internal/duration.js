/**
 * Duration parsing for session TTLs — adapter over the shared parser
 * that preserves this package's conventions: bare numbers are a
 * positive integer of **seconds** (backwards-compatible with the
 * `seal` API's TTL argument), duration strings resolve through
 * `@exortek/shared/duration`, and every result must be a positive
 * number of milliseconds.
 *
 * **Bare-numeric strings (`'900'`) are rejected** — the two branches
 * would otherwise disagree on unit for the same magnitude (`900` →
 * 900s, `'900'` → 900ms via the shared parser). Callers must pick
 * one form and stick to it: `900` for a bare integer of seconds, or
 * `'900s'` for the explicit-unit form.
 */

import { parseDuration as sharedParseDuration } from '@exortek/shared/duration';
import { isString } from '@exortek/shared/predicates';

import { invalidArgument } from './guards.js';

const BARE_NUMBER_RE = /^\s*-?\d+(?:\.\d+)?\s*$/;

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
      throw invalidArgument(`${name}: numeric duration must be a positive integer of seconds; got ${input}`);
    }
    return input * 1000;
  }
  if (isString(input)) {
    // Bare-numeric strings are ambiguous with the numeric branch above
    // (`900` → 900s here, but `'900'` → 900ms if it fell through to
    // the shared parser). Force the caller to commit to one form.
    if (BARE_NUMBER_RE.test(input)) {
      throw invalidArgument(
        `${name}: bare-numeric string ${JSON.stringify(input)} is ambiguous — pass ${input} (bare integer = seconds) or ${JSON.stringify(input + 's')} (explicit seconds suffix)`,
      );
    }
    let ms;
    try {
      ms = sharedParseDuration(input);
    } catch (err) {
      throw invalidArgument(
        `${name}: duration string ${JSON.stringify(input)} does not parse — use '<number><ms|s|m|h|d|w>'`,
        { cause: err },
      );
    }
    if (ms <= 0) {
      throw invalidArgument(`${name}: duration must be positive; got ${input}`);
    }
    return ms;
  }
  throw invalidArgument(`${name}: must be a positive integer of seconds or a duration string (got ${typeof input})`);
}
