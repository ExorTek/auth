import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  PATH_TRAVERSAL: 'PATH_TRAVERSAL',
  BODY_TOO_LARGE: 'BODY_TOO_LARGE',
  REQUEST_TIMEOUT: 'REQUEST_TIMEOUT',
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
