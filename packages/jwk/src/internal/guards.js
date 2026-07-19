/**
 * Argument guards bound to `JwkError` — the package-wide binding of
 * `@exortek/shared/asserts`. Import guards from here, never from the
 * shared module directly: every argument-shape failure must throw
 * `JwkError` with `ErrorCode.INVALID_ARGUMENT` so callers get one
 * error class for the whole package.
 */

import { defineGuards } from '@exortek/shared/asserts';
import { JwkError, ErrorCode } from './errors.js';

export const { invalidArgument, parse, assertObject } = defineGuards(JwkError, ErrorCode.INVALID_ARGUMENT);
