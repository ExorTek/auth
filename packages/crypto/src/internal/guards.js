/**
 * Argument guards bound to `CryptoError` — the package-wide binding of
 * `@exortek/shared/asserts`. Import guards from here, never from the
 * shared module directly: every argument-shape failure must throw
 * `CryptoError` with `ErrorCode.INVALID_ARGUMENT` so callers get one
 * error class for the whole package.
 */

import { defineGuards } from '@exortek/shared/asserts';
import { CryptoError, ErrorCode } from '../errors.js';

export const {
  invalidArgument,
  parse,
  assertNonNegativeInt,
  assertPositiveInt,
  assertUint48,
  assertString,
  assertNonEmptyString,
  assertObject,
  assertOptionalObject,
  assertBytes,
  assertBytesOrString,
  assertEncoding,
} = defineGuards(CryptoError, ErrorCode.INVALID_ARGUMENT);

/**
 * Construct (not throw) a `CryptoError(INVALID_KEY, msg)` — for key-shape
 * failures at the boundary of `cipher/*` and other key-consuming surfaces.
 * Distinct from `invalidArgument` so callers can branch on `err.code` when
 * "bad option" and "bad key" mean different remediation.
 *
 * @param {string} msg
 * @param {{ cause?: unknown }} [extra]
 * @returns {CryptoError}
 */
export function invalidKey(msg, extra) {
  return extra?.cause !== undefined
    ? new CryptoError(ErrorCode.INVALID_KEY, msg, { cause: extra.cause })
    : new CryptoError(ErrorCode.INVALID_KEY, msg);
}
