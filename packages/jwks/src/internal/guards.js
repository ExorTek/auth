import { makeAssertNonEmptyString, makeAssertObject, makeInvalidArgument } from '@exortek/shared/asserts';
import { JwksError, ErrorCode } from '../errors.js';

/**
 * Bind every guard this package calls to JwksError, so an argument-shape
 * failure anywhere carries one class and one code to branch on.
 *
 * @type {import('@exortek/shared/asserts').WrapFn}
 */
const wrap = (message, extra) => new JwksError(ErrorCode.INVALID_ARGUMENT, message, extra);

export const assertNonEmptyString = makeAssertNonEmptyString(wrap);
export const assertObject = makeAssertObject(wrap);
export const invalidArgument = makeInvalidArgument(wrap);
