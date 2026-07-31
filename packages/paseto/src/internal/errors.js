/**
 * Stable machine-readable codes for every failure that `@exortek/paseto`
 * can raise. Branch on `code`, never on the message.
 */
import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  INVALID_TOKEN: 'INVALID_TOKEN',
  INVALID_KEY: 'INVALID_KEY',
  UNSUPPORTED_VERSION: 'UNSUPPORTED_VERSION',
  DECRYPTION_FAILED: 'DECRYPTION_FAILED',
  SIGNATURE_INVALID: 'SIGNATURE_INVALID',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  NOT_YET_VALID: 'NOT_YET_VALID',
  CLAIM_MISMATCH: 'CLAIM_MISMATCH',
  // token-pair
  STORE_ERROR: 'STORE_ERROR',
  REVOKED: 'REVOKED',
  REFRESH_REUSED: 'REFRESH_REUSED',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * `code` (from {@link ErrorCode}) and a `status` — the HTTP response
 * status a middleware layer would use when translating the error.
 */
export class PasetoError extends BaseError {
  static statuses = {
    [ErrorCode.INVALID_ARGUMENT]: 400,
    [ErrorCode.UNSUPPORTED_VERSION]: 400,
    [ErrorCode.INVALID_TOKEN]: 401,
    [ErrorCode.INVALID_KEY]: 401,
    [ErrorCode.DECRYPTION_FAILED]: 401,
    [ErrorCode.SIGNATURE_INVALID]: 401,
    [ErrorCode.TOKEN_EXPIRED]: 401,
    [ErrorCode.NOT_YET_VALID]: 401,
    [ErrorCode.CLAIM_MISMATCH]: 401,
    [ErrorCode.REVOKED]: 401,
    [ErrorCode.REFRESH_REUSED]: 401,
    [ErrorCode.STORE_ERROR]: 500,
  };
  static defaultStatus = 500;
}
