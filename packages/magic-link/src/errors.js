/**
 * Stable machine-readable codes for every programmer-error failure that
 * `@exortek/magic-link` can raise. Branch on `code`, never on the
 * message. Expected verify failures (bad signature, expired,
 * consumed, mismatched email) are NOT thrown — `verifyMagicLink`
 * returns `{ valid: false, reason }` so a wrong or stale link is a
 * normal auth outcome, not an exception.
 */
import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  INVALID_SECRET: 'INVALID_SECRET',
  INVALID_PREFIX: 'INVALID_PREFIX',
  RATE_LIMITED: 'RATE_LIMITED',
  STORE_ERROR: 'STORE_ERROR',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * `code` (from {@link ErrorCode}) and a `status` — the HTTP response
 * status a middleware layer would use when translating the error.
 */
export class MagicLinkError extends BaseError {
  static statuses = {
    [ErrorCode.INVALID_ARGUMENT]: 400,
    [ErrorCode.INVALID_SECRET]: 400,
    [ErrorCode.INVALID_PREFIX]: 400,
    [ErrorCode.RATE_LIMITED]: 429,
    [ErrorCode.STORE_ERROR]: 500,
  };
  static defaultStatus = 500;
}
