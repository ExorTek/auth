/**
 * Argument guards bound to `PasskeyError` — the package-wide binding of
 * `@exortek/shared/asserts`. Import guards from here, never from the
 * shared module directly: every argument-shape failure must throw
 * `PasskeyError` with `ErrorCode.INVALID_ARGUMENT` so callers get one
 * error class for the whole package.
 */

import { defineGuards } from '@exortek/shared/asserts';
import { PasskeyError, ErrorCode } from '../errors.js';

export const { invalidArgument, assertObject, assertNonEmptyString } = defineGuards(
  PasskeyError,
  ErrorCode.INVALID_ARGUMENT,
);
