/**
 * Argument guards bound to `PasetoError` — the package-wide binding of
 * `@exortek/shared/asserts`. Import guards from here, never from the
 * shared module directly: every argument-shape failure must throw
 * `PasetoError` with `ErrorCode.INVALID_ARGUMENT` so callers get one
 * error class for the whole package.
 */

import { defineGuards } from '@exortek/shared/asserts';
import { PasetoError, ErrorCode } from './errors.js';

export const { invalidArgument, assertObject, assertNonEmptyString } = defineGuards(
  PasetoError,
  ErrorCode.INVALID_ARGUMENT,
);
