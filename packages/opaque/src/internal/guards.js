/**
 * Argument guards bound to `OpaqueError` — the package-wide binding of
 * `@exortek/shared/asserts`. Import guards from here, never from the
 * shared module directly: every argument-shape failure must throw
 * `OpaqueError` with `ErrorCode.INVALID_ARGUMENT` so callers get one
 * error class for the whole package.
 */

import {
  makeInvalidArgument,
  makeAssertObject,
  makeAssertNonEmptyString,
  makeAssertPositiveInt,
} from '@exortek/shared/asserts';
import { OpaqueError, ErrorCode } from '../errors.js';

/**
 * Bind every guard this package calls to OpaqueError, so an argument-shape
 * failure anywhere carries one class and one code to branch on.
 *
 * @type {import('@exortek/shared/asserts').WrapFn}
 */
const wrap = (message, extra) => new OpaqueError(ErrorCode.INVALID_ARGUMENT, message, extra);

export const invalidArgument = makeInvalidArgument(wrap);
export const assertObject = makeAssertObject(wrap);
export const assertNonEmptyString = makeAssertNonEmptyString(wrap);
export const assertPositiveInt = makeAssertPositiveInt(wrap);
