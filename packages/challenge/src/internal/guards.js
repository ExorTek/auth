/**
 * Argument guards bound to `ChallengeError` — the package-wide binding
 * of `@exortek/shared/asserts`. Import guards from here, never from the
 * shared module directly: every argument-shape failure must throw
 * `ChallengeError` with `ErrorCode.INVALID_ARGUMENT` so callers get one
 * error class for the whole package.
 */

import { defineGuards } from '@exortek/shared/asserts';
import { ChallengeError, ErrorCode } from '../errors.js';

export const { invalidArgument, parse, assertObject, assertNonEmptyString, assertBytes } = defineGuards(
  ChallengeError,
  ErrorCode.INVALID_ARGUMENT,
);
