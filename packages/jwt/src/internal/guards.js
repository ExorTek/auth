/**
 * Argument guards bound to `JwtError` — the package-wide binding of
 * `@exortek/shared/asserts`. Import guards from here, never from the
 * shared module directly: every argument-shape failure must throw
 * `JwtError` with `ErrorCode.INVALID_ARGUMENT` so callers get one
 * error class for the whole package.
 */

import { defineGuards } from '@exortek/shared/asserts';
import { JwtError, ErrorCode } from './errors.js';

export const { invalidArgument, assertNonEmptyString, assertObject, assertPositiveInt, assertString } = defineGuards(
  JwtError,
  ErrorCode.INVALID_ARGUMENT,
);
