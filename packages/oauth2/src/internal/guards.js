/**
 * Small argument guards shared across the flow helpers. They throw
 * {@link OAuth2Error} with `INVALID_ARGUMENT` so a caller passing a bad
 * option gets a stable, branchable failure instead of a downstream
 * `TypeError` from deep inside the crypto layer.
 */
import { isInteger, isNonEmptyString } from '@exortek/shared/predicates';

import { ErrorCode, OAuth2Error } from './errors.js';

/**
 * @param {unknown} value
 * @param {string} label  identifier used in the error message
 * @returns {string}
 */
export function requireNonEmptyString(value, label) {
  if (!isNonEmptyString(value)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, `${label} must be a non-empty string`);
  }
  return value;
}

/**
 * @param {unknown} value
 * @param {string} label  identifier used in the error message
 * @param {number} min    inclusive lower bound
 * @returns {number}
 */
export function requireIntegerAtLeast(value, label, min) {
  if (!isInteger(value) || value < min) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, `${label} must be an integer >= ${min}`);
  }
  return value;
}
