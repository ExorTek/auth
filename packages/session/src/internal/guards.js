/**
 * Argument guards bound to `SessionError` — the package-wide binding
 * of `@exortek/shared/asserts`. Import guards from here, never from
 * the shared module directly: every argument-shape failure must throw
 * `SessionError` with `ErrorCode.INVALID_ARGUMENT` so callers get one
 * error class for the whole package.
 */

import { defineGuards } from '@exortek/shared/asserts';
import { SessionError, ErrorCode } from '../errors.js';

export const { invalidArgument, parse, assertNonEmptyString, assertObject } = defineGuards(
  SessionError,
  ErrorCode.INVALID_ARGUMENT,
);
