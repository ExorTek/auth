/**
 * Stable machine-readable codes for every failure that
 * `@exortek/session` can raise. Branch on `code`, never on the message
 * text — messages are free-form and change across versions.
 */
import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  INVALID_TOKEN: 'INVALID_TOKEN',
  EXPIRED: 'EXPIRED',
  SESSION_NOT_FOUND: 'SESSION_NOT_FOUND',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * {@link ErrorCode} `code` (branch on this) and a `status` — the HTTP
 * response status a middleware layer would use when translating the
 * error into a response.
 *
 * @example
 * try {
 *   const session = await sessions.verify(req)
 * } catch (err) {
 *   if (err instanceof SessionError) {
 *     if (err.code === ErrorCode.EXPIRED) return res.redirect('/login?expired=1')
 *   }
 *   throw err
 * }
 */
export class SessionError extends BaseError {
  static statuses = {
    [ErrorCode.INVALID_ARGUMENT]: 400,
    [ErrorCode.INVALID_TOKEN]: 401,
    [ErrorCode.EXPIRED]: 401,
    [ErrorCode.SESSION_NOT_FOUND]: 401,
  };
  static defaultStatus = 500;
}
