/**
 * Argument guards bound to `SecurityError` — the package-wide binding
 * of `@exortek/shared/asserts`. Import guards from here, never from
 * the shared module directly: every argument-shape failure must throw
 * `SecurityError` with `ErrorCode.INVALID_ARGUMENT` so callers get one
 * error class for the whole package.
 */

import { defineGuards } from '@exortek/shared/asserts';
import { SecurityError, ErrorCode } from './errors.js';

export const { invalidArgument, parse, assertNonEmptyString, assertObject, assertString } = defineGuards(
  SecurityError,
  ErrorCode.INVALID_ARGUMENT,
);
