import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  FETCH_FAILED: 'FETCH_FAILED',
  KID_NOT_FOUND: 'KID_NOT_FOUND',
});

export class JwksError extends BaseError {
  static statuses = {
    [ErrorCode.INVALID_ARGUMENT]: 400,
    [ErrorCode.FETCH_FAILED]: 502,
    [ErrorCode.KID_NOT_FOUND]: 401,
  };
  static defaultStatus = 500;
}
