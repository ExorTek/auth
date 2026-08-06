/**
 * Argument guards bound to `CryptoError` — the package-wide binding of
 * `@exortek/shared/asserts`. Import guards from here, never from the
 * shared module directly: every argument-shape failure must throw
 * `CryptoError` with `ErrorCode.INVALID_ARGUMENT` so callers get one
 * error class for the whole package.
 */

import {
  makeInvalidArgument,
  makeParse,
  makeAssertNonNegativeInt,
  makeAssertPositiveInt,
  makeAssertUint48,
  makeAssertString,
  makeAssertNonEmptyString,
  makeAssertObject,
  makeAssertOptionalObject,
  makeAssertBytes,
  makeAssertBytesOrString,
  makeAssertEncoding,
} from '@exortek/shared/asserts';
import { CryptoError, ErrorCode } from '../errors.js';

/**
 * Bind every guard this package calls to CryptoError, so an argument-shape
 * failure anywhere carries one class and one code to branch on.
 *
 * @type {import('@exortek/shared/asserts').WrapFn}
 */
const wrap = (message, extra) => new CryptoError(ErrorCode.INVALID_ARGUMENT, message, extra);

export const invalidArgument = makeInvalidArgument(wrap);
export const parse = makeParse(wrap);
export const assertNonNegativeInt = makeAssertNonNegativeInt(wrap);
export const assertPositiveInt = makeAssertPositiveInt(wrap);
export const assertUint48 = makeAssertUint48(wrap);
export const assertString = makeAssertString(wrap);
export const assertNonEmptyString = makeAssertNonEmptyString(wrap);
export const assertObject = makeAssertObject(wrap);
export const assertOptionalObject = makeAssertOptionalObject(wrap);
export const assertBytes = makeAssertBytes(wrap);
export const assertBytesOrString = makeAssertBytesOrString(wrap);
export const assertEncoding = makeAssertEncoding(wrap);

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
