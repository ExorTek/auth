import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  CSRF_MISSING: 'CSRF_MISSING',
  CSRF_MISMATCH: 'CSRF_MISMATCH',
  CSRF_MALFORMED: 'CSRF_MALFORMED',
  CSRF_TAMPERED: 'CSRF_TAMPERED',
  RATE_LIMITED: 'RATE_LIMITED',
  ORIGIN_DENIED: 'ORIGIN_DENIED',
  REDIRECT_UNSAFE: 'REDIRECT_UNSAFE',
  PATH_TRAVERSAL: 'PATH_TRAVERSAL',
  BODY_TOO_LARGE: 'BODY_TOO_LARGE',
  REQUEST_TIMEOUT: 'REQUEST_TIMEOUT',
  WEBHOOK_INVALID: 'WEBHOOK_INVALID',
  HONEYPOT_TRIGGERED: 'HONEYPOT_TRIGGERED',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * `code` (from {@link ErrorCode}) and an HTTP `status` (400 unless
 * overridden via `options.status`).
 */
export class SecurityError extends BaseError {
  static statuses = {};
  static defaultStatus = 400;
}
