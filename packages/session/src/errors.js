/**
 * Stable machine-readable codes for every failure that
 * `@exortek/session` can raise. Branch on `code`, never on the message
 * text — messages are free-form and change across versions.
 */
import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',

  // Token / cookie problems
  MISSING_TOKEN: 'MISSING_TOKEN',
  INVALID_TOKEN: 'INVALID_TOKEN',
  EXPIRED: 'EXPIRED',
  IDLE_TIMEOUT: 'IDLE_TIMEOUT',

  // Store state
  REVOKED: 'REVOKED',
  SESSION_NOT_FOUND: 'SESSION_NOT_FOUND',
  TOKEN_ROTATION_REQUIRED: 'TOKEN_ROTATION_REQUIRED',

  // Bindings
  FINGERPRINT_MISMATCH: 'FINGERPRINT_MISMATCH',
  SUSPICIOUS_ACTIVITY: 'SUSPICIOUS_ACTIVITY',

  // Policy
  CONCURRENT_LIMIT_EXCEEDED: 'CONCURRENT_LIMIT_EXCEEDED',
  FRESH_AUTH_REQUIRED: 'FRESH_AUTH_REQUIRED',
  IMPERSONATION_INVALID: 'IMPERSONATION_INVALID',

  // Infra
  MISSING_PEER_DEP: 'MISSING_PEER_DEP',
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
 *     if (err.code === ErrorCode.FRESH_AUTH_REQUIRED) return res.redirect('/reauth')
 *     if (err.code === ErrorCode.EXPIRED)             return res.redirect('/login?expired=1')
 *   }
 *   throw err
 * }
 */
export class SessionError extends BaseError {
  static statuses = {
    [ErrorCode.INVALID_ARGUMENT]: 400,
    [ErrorCode.MISSING_TOKEN]: 401,
    [ErrorCode.INVALID_TOKEN]: 401,
    [ErrorCode.EXPIRED]: 401,
    [ErrorCode.IDLE_TIMEOUT]: 401,
    [ErrorCode.REVOKED]: 401,
    [ErrorCode.SESSION_NOT_FOUND]: 401,
    [ErrorCode.TOKEN_ROTATION_REQUIRED]: 401,
    [ErrorCode.FINGERPRINT_MISMATCH]: 401,
    [ErrorCode.SUSPICIOUS_ACTIVITY]: 401,
    [ErrorCode.CONCURRENT_LIMIT_EXCEEDED]: 401,
    [ErrorCode.FRESH_AUTH_REQUIRED]: 401,
    [ErrorCode.IMPERSONATION_INVALID]: 403,
    [ErrorCode.MISSING_PEER_DEP]: 500,
  };
  static defaultStatus = 500;
}
