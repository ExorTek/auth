/**
 * Stable machine-readable codes for every failure that `@exortek/jwt`
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

  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  TOKEN_NOT_YET_VALID: 'TOKEN_NOT_YET_VALID',
  TOKEN_TOO_OLD: 'TOKEN_TOO_OLD',
  TOKEN_TOO_LARGE: 'TOKEN_TOO_LARGE',

  INVALID_ISSUER: 'INVALID_ISSUER',
  INVALID_AUDIENCE: 'INVALID_AUDIENCE',
  INVALID_SUBJECT: 'INVALID_SUBJECT',
  INVALID_NONCE: 'INVALID_NONCE',
  INVALID_TYP: 'INVALID_TYP',
  INSUFFICIENT_SCOPE: 'INSUFFICIENT_SCOPE',
  MISSING_CLAIM: 'MISSING_CLAIM',

  CRIT_UNSUPPORTED: 'CRIT_UNSUPPORTED',
  KEY_NOT_FOUND: 'KEY_NOT_FOUND',

  REFRESH_REUSED: 'REFRESH_REUSED',
  REVOKED: 'REVOKED',
  STORE_ERROR: 'STORE_ERROR',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * `code` (from {@link ErrorCode}) and a `status` — the HTTP response
 * status a middleware layer would use when translating the error.
 */
export class JwtError extends BaseError {
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
    [ErrorCode.TOKEN_EXPIRED]: 401,
    [ErrorCode.TOKEN_NOT_YET_VALID]: 401,
    [ErrorCode.TOKEN_TOO_OLD]: 401,
    [ErrorCode.INVALID_ISSUER]: 401,
    [ErrorCode.INVALID_AUDIENCE]: 401,
    [ErrorCode.INVALID_SUBJECT]: 401,
    [ErrorCode.INVALID_NONCE]: 401,
    [ErrorCode.INVALID_TYP]: 401,
    [ErrorCode.MISSING_CLAIM]: 401,
    [ErrorCode.REFRESH_REUSED]: 401,
    [ErrorCode.REVOKED]: 401,
    [ErrorCode.INSUFFICIENT_SCOPE]: 403,
    [ErrorCode.TOKEN_TOO_LARGE]: 413,
    [ErrorCode.STORE_ERROR]: 500,
  };
  static defaultStatus = 500;
}
