/**
 * Seconds-returning duration parser for token-pair store TTLs. The
 * refresh registry keys entries by an integer NumericDate (seconds since
 * epoch) regardless of PASETO's ISO 8601 claim format, so store bookkeeping
 * needs seconds. Thin adapter over the shared millisecond parser: bare
 * numbers pass through as seconds; unit suffixes delegate and ÷1000.
 */

import { parseDuration as sharedParseDuration } from '@exortek/shared/duration';
import { invalidArgument } from './guards.js';

const BARE_NUMBER_RE = /^\s*(-?\d+(?:\.\d+)?)\s*$/;

/**
 * @param {string | number} input
 * @returns {number} seconds
 */
export function parseDurationSeconds(input) {
  if (typeof input === 'number') {
    if (!Number.isFinite(input)) {
      throw invalidArgument(`parseDuration: numeric input must be finite; got ${input}`);
    }
    return input;
  }
  if (typeof input !== 'string') {
    throw invalidArgument(`parseDuration: expected string or number; got ${typeof input}`);
  }
  const bare = BARE_NUMBER_RE.exec(input);
  if (bare) {
    return Number(bare[1]);
  }
  try {
    return sharedParseDuration(input) / 1000;
  } catch (err) {
    throw invalidArgument(err instanceof Error ? err.message : String(err), { cause: err });
  }
}
