import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
});

export class PasskeyError extends BaseError {
  static statuses = {
    [ErrorCode.INVALID_ARGUMENT]: 400,
  };
  static defaultStatus = 500;
}
