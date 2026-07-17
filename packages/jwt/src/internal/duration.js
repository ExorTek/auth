/**
 * Human-duration parser — `'15m'`, `'7d'`, `'2h'`, `'500ms'`, `'30s'`.
 * Scaffold stub. Returns seconds (integer) for JWT NumericDate arithmetic.
 * Bare numbers are treated as seconds.
 *
 * Supported suffixes: `ms`, `s`, `m`, `h`, `d`, `w`.
 */

import { JwtError, ErrorCode } from './errors.js';

/**
 * @param {string | number} _input
 * @returns {number}       seconds
 */
export function parseDuration(_input) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'duration.parseDuration: not implemented');
}
