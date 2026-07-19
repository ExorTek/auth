/**
 * Argument guards bound to `PasswordError` — the package-wide binding
 * of `@exortek/shared/asserts`. Import guards from here, never from
 * the shared module directly: every argument-shape failure must throw
 * `PasswordError` with `ErrorCode.INVALID_ARGUMENT` so callers get one
 * error class for the whole package.
 */

import { bindAsserts } from '@exortek/shared/asserts';
import { PasswordError, ErrorCode } from '../errors.js';

const bound = bindAsserts(m => new PasswordError(ErrorCode.INVALID_ARGUMENT, m));

export const {
  invalidArgument,
  parse,
  assertPositiveInt,
  assertString,
  assertNonEmptyString,
  assertBytesOrString,
  assertFunction,
  assertObject,
} = bound;
