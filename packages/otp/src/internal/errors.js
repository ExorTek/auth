/**
 * Stable machine-readable codes for every failure that `@exortek/otp`
 * can raise. Branch on `code`, never on the message.
 */
import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  INVALID_SECRET: 'INVALID_SECRET',
  UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * `code` (from {@link ErrorCode}) and a `status` — the HTTP response
 * status a middleware layer would use when translating the error.
 */
export class OtpError extends BaseError {
  static statuses = {
    [ErrorCode.INVALID_ARGUMENT]: 400,
    [ErrorCode.UNSUPPORTED_ALGORITHM]: 400,
    [ErrorCode.INVALID_SECRET]: 401,
  };
  static defaultStatus = 500;
}
