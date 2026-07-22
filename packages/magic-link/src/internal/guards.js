/**
 * Argument guards bound to `MagicLinkError` — the package-wide binding
 * of `@exortek/shared/asserts`.
 */

import { defineGuards } from '@exortek/shared/asserts';
import { MagicLinkError, ErrorCode } from '../errors.js';

export const { invalidArgument, parse, assertObject, assertNonEmptyString } = defineGuards(
  MagicLinkError,
  ErrorCode.INVALID_ARGUMENT,
);
