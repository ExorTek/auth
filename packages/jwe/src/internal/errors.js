/**
 * Stable machine-readable codes for every failure that `@exortek/jwe`
 * can raise. Branch on `code`, never on the message.
 */
import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  INVALID_TOKEN: 'INVALID_TOKEN',
  INVALID_HEADER: 'INVALID_HEADER',
  INVALID_KEY: 'INVALID_KEY',
  UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM',
  UNSUPPORTED_ENCRYPTION: 'UNSUPPORTED_ENCRYPTION',
  ALGORITHM_MISMATCH: 'ALGORITHM_MISMATCH',
  ENCRYPTION_MISMATCH: 'ENCRYPTION_MISMATCH',
  MISSING_ALG_ALLOWLIST: 'MISSING_ALG_ALLOWLIST',
  MISSING_ENC_ALLOWLIST: 'MISSING_ENC_ALLOWLIST',
  DECRYPTION_FAILED: 'DECRYPTION_FAILED',
  KEY_NOT_FOUND: 'KEY_NOT_FOUND',
  TOKEN_TOO_LARGE: 'TOKEN_TOO_LARGE',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  // Scaffold marker — thrown by the encrypt/decrypt/json placeholders until
  // the encryption core lands. Removed once every surface is implemented.
  NOT_IMPLEMENTED: 'NOT_IMPLEMENTED',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * `code` (from {@link ErrorCode}) and a `status` — the HTTP response
 * status a middleware layer would use when translating the error.
 */
export class JweError extends BaseError {
  static statuses = {
    [ErrorCode.INVALID_ARGUMENT]: 400,
    [ErrorCode.UNSUPPORTED_ALGORITHM]: 400,
    [ErrorCode.UNSUPPORTED_ENCRYPTION]: 400,
    [ErrorCode.MISSING_ALG_ALLOWLIST]: 400,
    [ErrorCode.MISSING_ENC_ALLOWLIST]: 400,
    [ErrorCode.INVALID_TOKEN]: 401,
    [ErrorCode.INVALID_HEADER]: 401,
    [ErrorCode.INVALID_KEY]: 401,
    [ErrorCode.ALGORITHM_MISMATCH]: 401,
    [ErrorCode.ENCRYPTION_MISMATCH]: 401,
    [ErrorCode.DECRYPTION_FAILED]: 401,
    [ErrorCode.KEY_NOT_FOUND]: 401,
    [ErrorCode.TOKEN_EXPIRED]: 401,
    [ErrorCode.TOKEN_TOO_LARGE]: 413,
    [ErrorCode.NOT_IMPLEMENTED]: 501,
  };
  static defaultStatus = 500;
}
