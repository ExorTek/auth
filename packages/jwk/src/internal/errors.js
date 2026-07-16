/**
 * Stable machine-readable codes for every failure that `@exortek/jwk`
 * can raise. Branch on `code`, never on the message.
 */
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
export class JwkError extends Error {
  /**
   * @param {string} code    One of {@link ErrorCode}.
   * @param {string} message Human-readable diagnostic. Free-form; may
   *                         change across versions. Branch on `code`.
   * @param {{ cause?: unknown, status?: number }} [options]
   */
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'JwkError';
    this.code = code;
    this.status = options.status ?? statusFor(code);
  }
}

function statusFor(code) {
  switch (code) {
    case ErrorCode.INVALID_ARGUMENT:
    case ErrorCode.UNSUPPORTED_KTY:
    case ErrorCode.UNSUPPORTED_CURVE:
    case ErrorCode.UNSUPPORTED_ALGORITHM:
    case ErrorCode.INVALID_FORMAT:
    case ErrorCode.MISSING_REQUIRED_MEMBER:
    case ErrorCode.KEY_OPS_CONFLICT:
      return 400;
    case ErrorCode.INVALID_KEY:
    case ErrorCode.INVALID_JWK:
      return 400;
    default:
      return 500;
  }
}
