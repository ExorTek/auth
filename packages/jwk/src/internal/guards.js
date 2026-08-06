/**
 * Argument guards bound to `JwkError` — the package-wide binding of
 * `@exortek/shared/asserts`. Import guards from here, never from the
 * shared module directly: every argument-shape failure must throw
 * `JwkError` with `ErrorCode.INVALID_ARGUMENT` so callers get one
 * error class for the whole package.
 */

import { makeInvalidArgument, makeParse, makeAssertObject } from '@exortek/shared/asserts';
import { JwkError, ErrorCode } from './errors.js';

/**
 * Bind every guard this package calls to JwkError, so an argument-shape
 * failure anywhere carries one class and one code to branch on.
 *
 * @type {import('@exortek/shared/asserts').WrapFn}
 */
const wrap = (message, extra) => new JwkError(ErrorCode.INVALID_ARGUMENT, message, extra);

export const invalidArgument = makeInvalidArgument(wrap);
export const parse = makeParse(wrap);
export const assertObject = makeAssertObject(wrap);
