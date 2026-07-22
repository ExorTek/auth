/**
 * Argument guards bound to `ApiKeyError` — the package-wide binding of
 * `@exortek/shared/asserts`. Import guards from here, never from the
 * shared module directly.
 */

import { defineGuards } from '@exortek/shared/asserts';
import { ApiKeyError, ErrorCode } from '../errors.js';

export const { invalidArgument, parse, assertObject, assertNonEmptyString } = defineGuards(
  ApiKeyError,
  ErrorCode.INVALID_ARGUMENT,
);
