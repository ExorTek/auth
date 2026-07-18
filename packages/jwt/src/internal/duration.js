/**
 * Human-duration parser for JWT `expiresIn` / `notBefore` /
 * `clockTolerance` / `maxAge`. Returns **seconds** — matches RFC
 * 7519's NumericDate for `exp` / `nbf` / `iat` arithmetic.
 *
 * Thin adapter over the shared millisecond parser that preserves this
 * package's historical convention: bare numbers pass through unchanged
 * (already in seconds) and bare numeric strings (`'60'`) parse as
 * seconds; everything with a unit suffix is delegated to
 * `@exortek/shared/duration` and divided by 1000.
 *
 * Failures surface as typed {@link ErrorCode.INVALID_ARGUMENT}.
 */

import { parseDuration as sharedParseDuration } from '@exortek/shared/duration';
import { JwtError, ErrorCode } from './errors.js';

const BARE_NUMBER_RE = /^\s*(-?\d+(?:\.\d+)?)\s*$/;

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
  const bare = BARE_NUMBER_RE.exec(input);
  if (bare) {
    return Number(bare[1]);
  }
  try {
    return sharedParseDuration(input) / 1000;
  } catch (err) {
    throw new JwtError(ErrorCode.INVALID_ARGUMENT, err instanceof Error ? err.message : String(err));
  }
}
