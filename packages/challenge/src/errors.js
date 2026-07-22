/**
 * Stable machine-readable codes for every programmer-error failure that
 * `@exortek/challenge` can raise. Branch on `code`, never on the
 * message. Note: expected verify failures (bad signature, expired,
 * mismatched claim) are NOT thrown — `verifyChallenge` returns
 * `{ valid: false, reason }` for those so a wrong or stale token is a
 * normal auth outcome, not an exception. Errors below fire only when
 * the caller configured something wrong.
 */
import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  INVALID_SECRET: 'INVALID_SECRET',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * `code` (from {@link ErrorCode}) and a `status` — the HTTP response
 * status a middleware layer would use when translating the error.
 */
export class ChallengeError extends BaseError {
  static statuses = {
    [ErrorCode.INVALID_ARGUMENT]: 400,
    [ErrorCode.INVALID_SECRET]: 400,
  };
  static defaultStatus = 500;
}
