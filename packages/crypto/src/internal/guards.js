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
  assertBoolean,
  assertFunction,
  assertObject,
  assertOptionalObject,
  assertBytes,
  assertBytesOrString,
  assertEncoding,
} = defineGuards(CryptoError, ErrorCode.INVALID_ARGUMENT);
