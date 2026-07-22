/**
 * Stable machine-readable codes for every programmer-error failure that
 * `@exortek/apikey` can raise. Branch on `code`, never on the message.
 * Note: expected verify failures (bad secret, expired, revoked,
 * missing scope) are NOT thrown — `verifyApiKey` returns
 * `{ valid: false, reason }` so a wrong or stale key is a normal auth
 * outcome, not an exception. Errors below fire only when the caller
 * configured something wrong or the store misbehaved.
 */
import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  INVALID_PREFIX: 'INVALID_PREFIX',
  INVALID_PEPPER: 'INVALID_PEPPER',
  STORE_ERROR: 'STORE_ERROR',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * `code` (from {@link ErrorCode}) and a `status` — the HTTP response
 * status a middleware layer would use when translating the error.
 */
export class ApiKeyError extends BaseError {
  static statuses = {
    [ErrorCode.INVALID_ARGUMENT]: 400,
    [ErrorCode.INVALID_PREFIX]: 400,
    [ErrorCode.INVALID_PEPPER]: 400,
    [ErrorCode.STORE_ERROR]: 500,
  };
  static defaultStatus = 500;
}
