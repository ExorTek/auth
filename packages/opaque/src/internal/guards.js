/**
 * Argument guards bound to `OpaqueError` — the package-wide binding of
 * `@exortek/shared/asserts`. Import guards from here, never from the
 * shared module directly: every argument-shape failure must throw
 * `OpaqueError` with `ErrorCode.INVALID_ARGUMENT` so callers get one
 * error class for the whole package.
 */

import { defineGuards } from '@exortek/shared/asserts';
import { OpaqueError, ErrorCode } from '../errors.js';

export const { invalidArgument, assertObject, assertNonEmptyString, assertPositiveInt } = defineGuards(
  OpaqueError,
  ErrorCode.INVALID_ARGUMENT,
);
