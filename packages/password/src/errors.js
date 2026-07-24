/**
 * Stable machine-readable codes for every failure that `@exortek/password`
 * can raise. Branch on `code`, never on the message text — messages are
 * free-form and change across versions.
 */
import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM',
  MISSING_PEER_DEP: 'MISSING_PEER_DEP',
  PASSWORD_TOO_LONG: 'PASSWORD_TOO_LONG',
  POLICY_VIOLATION: 'POLICY_VIOLATION',
  HIBP_UNAVAILABLE: 'HIBP_UNAVAILABLE',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * {@link ErrorCode} `code` (branch on this) and a `status` — the HTTP
 * response status a middleware layer would use when translating the
 * error into a response.
 *
 * @example
 * try {
 *   await password.verify(input, storedHash)
 * } catch (err) {
 *   if (err instanceof PasswordError && err.code === ErrorCode.MISSING_PEER_DEP) {
 *     // stored hash was minted with an algo whose peer isn't installed
 *     logger.warn({ err }, 'install argon2 to verify legacy hashes')
 *   }
 *   throw err
 * }
 */
export class PasswordError extends BaseError {
  static statuses = {
    [ErrorCode.INVALID_ARGUMENT]: 400,
    [ErrorCode.UNSUPPORTED_ALGORITHM]: 400,
    [ErrorCode.PASSWORD_TOO_LONG]: 400,
    [ErrorCode.POLICY_VIOLATION]: 400,
    [ErrorCode.MISSING_PEER_DEP]: 500,
    [ErrorCode.HIBP_UNAVAILABLE]: 500,
  };
  static defaultStatus = 500;
}
