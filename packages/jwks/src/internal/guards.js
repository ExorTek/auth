import { defineGuards } from '@exortek/shared/asserts';
import { JwksError, ErrorCode } from '../errors.js';

export const { assertNonEmptyString, assertObject, invalidArgument } = defineGuards(
  JwksError,
  ErrorCode.INVALID_ARGUMENT,
);
