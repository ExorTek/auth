/**
 * Stable machine-readable codes for every failure that `@exortek/jwk`
 * can raise. Branch on `code`, never on the message.
 */
import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  UNSUPPORTED_KTY: 'UNSUPPORTED_KTY',
  UNSUPPORTED_CURVE: 'UNSUPPORTED_CURVE',
  UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM',
  INVALID_KEY: 'INVALID_KEY',
  INVALID_JWK: 'INVALID_JWK',
  INVALID_FORMAT: 'INVALID_FORMAT',
  MISSING_REQUIRED_MEMBER: 'MISSING_REQUIRED_MEMBER',
  KEY_OPS_CONFLICT: 'KEY_OPS_CONFLICT',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * `code` (from {@link ErrorCode}) and a `status` — the HTTP response
 * status a middleware layer would use when translating the error.
 */
export class JwkError extends BaseError {
  static statuses = {
    [ErrorCode.INVALID_ARGUMENT]: 400,
    [ErrorCode.UNSUPPORTED_KTY]: 400,
    [ErrorCode.UNSUPPORTED_CURVE]: 400,
    [ErrorCode.UNSUPPORTED_ALGORITHM]: 400,
    [ErrorCode.INVALID_FORMAT]: 400,
    [ErrorCode.MISSING_REQUIRED_MEMBER]: 400,
    [ErrorCode.KEY_OPS_CONFLICT]: 400,
    [ErrorCode.INVALID_KEY]: 400,
    [ErrorCode.INVALID_JWK]: 400,
  };
  static defaultStatus = 500;
}
