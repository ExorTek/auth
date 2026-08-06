/**
 * Argument guards bound to `ApiKeyError` — the package-wide binding of
 * `@exortek/shared/asserts`. Import guards from here, never from the
 * shared module directly.
 */

import { makeInvalidArgument, makeParse, makeAssertObject, makeAssertNonEmptyString } from '@exortek/shared/asserts';
import { ApiKeyError, ErrorCode } from '../errors.js';

/**
 * Bind every guard this package calls to ApiKeyError, so an argument-shape
 * failure anywhere carries one class and one code to branch on.
 *
 * @type {import('@exortek/shared/asserts').WrapFn}
 */
const wrap = (message, extra) => new ApiKeyError(ErrorCode.INVALID_ARGUMENT, message, extra);

export const invalidArgument = makeInvalidArgument(wrap);
export const parse = makeParse(wrap);
export const assertObject = makeAssertObject(wrap);
export const assertNonEmptyString = makeAssertNonEmptyString(wrap);
