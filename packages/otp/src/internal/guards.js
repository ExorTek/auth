/**
 * Argument guards bound to `OtpError` — the package-wide binding of
 * `@exortek/shared/asserts`. Import guards from here, never from the
 * shared module directly: every argument-shape failure must throw
 * `OtpError` with `ErrorCode.INVALID_ARGUMENT` so callers get one
 * error class for the whole package.
 */

import { defineGuards } from '@exortek/shared/asserts';
import { OtpError, ErrorCode } from './errors.js';

export const { invalidArgument, parse, assertObject, assertNonEmptyString } = defineGuards(
  OtpError,
  ErrorCode.INVALID_ARGUMENT,
);
