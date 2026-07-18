/**
 * Stable machine-readable codes for every failure that `@exortek/jws`
 * can raise. Branch on `code`, never on the message.
 */
import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  INVALID_TOKEN: 'INVALID_TOKEN',
  INVALID_HEADER: 'INVALID_HEADER',
  INVALID_PAYLOAD: 'INVALID_PAYLOAD',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  INVALID_KEY: 'INVALID_KEY',
  UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM',
  ALGORITHM_MISMATCH: 'ALGORITHM_MISMATCH',
  ALGORITHM_NONE_FORBIDDEN: 'ALGORITHM_NONE_FORBIDDEN',
  MISSING_ALG_ALLOWLIST: 'MISSING_ALG_ALLOWLIST',
  CRIT_UNSUPPORTED: 'CRIT_UNSUPPORTED',
  KEY_NOT_FOUND: 'KEY_NOT_FOUND',
  TOKEN_TOO_LARGE: 'TOKEN_TOO_LARGE',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * `code` (from {@link ErrorCode}) and a `status` — the HTTP response
 * status a middleware layer would use when translating the error.
 */
export class JwsError extends BaseError {
  static statuses = {
    [ErrorCode.INVALID_ARGUMENT]: 400,
    [ErrorCode.UNSUPPORTED_ALGORITHM]: 400,
    [ErrorCode.MISSING_ALG_ALLOWLIST]: 400,
    [ErrorCode.INVALID_TOKEN]: 401,
    [ErrorCode.INVALID_HEADER]: 401,
    [ErrorCode.INVALID_PAYLOAD]: 401,
    [ErrorCode.INVALID_SIGNATURE]: 401,
    [ErrorCode.INVALID_KEY]: 401,
    [ErrorCode.ALGORITHM_MISMATCH]: 401,
    [ErrorCode.ALGORITHM_NONE_FORBIDDEN]: 401,
    [ErrorCode.CRIT_UNSUPPORTED]: 401,
    [ErrorCode.KEY_NOT_FOUND]: 401,
    [ErrorCode.TOKEN_TOO_LARGE]: 413,
  };
  static defaultStatus = 500;
}
