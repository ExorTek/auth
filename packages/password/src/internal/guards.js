/**
 * Argument guards bound to `PasswordError` — the package-wide binding
 * of `@exortek/shared/asserts`. Import guards from here, never from
 * the shared module directly: every argument-shape failure must throw
 * `PasswordError` with `ErrorCode.INVALID_ARGUMENT` so callers get one
 * error class for the whole package.
 */

import {
  makeInvalidArgument,
  makeParse,
  makeAssertPositiveInt,
  makeAssertString,
  makeAssertNonEmptyString,
  makeAssertBytesOrString,
  makeAssertFunction,
  makeAssertObject,
} from '@exortek/shared/asserts';
import { PasswordError, ErrorCode } from '../errors.js';

/**
 * Bind every guard this package calls to PasswordError, so an argument-shape
 * failure anywhere carries one class and one code to branch on.
 *
 * @type {import('@exortek/shared/asserts').WrapFn}
 */
const wrap = (message, extra) => new PasswordError(ErrorCode.INVALID_ARGUMENT, message, extra);

export const invalidArgument = makeInvalidArgument(wrap);
export const parse = makeParse(wrap);
export const assertPositiveInt = makeAssertPositiveInt(wrap);
export const assertString = makeAssertString(wrap);
export const assertNonEmptyString = makeAssertNonEmptyString(wrap);
export const assertBytesOrString = makeAssertBytesOrString(wrap);
export const assertFunction = makeAssertFunction(wrap);
export const assertObject = makeAssertObject(wrap);
