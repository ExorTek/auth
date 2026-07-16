/**
 * Stable machine-readable codes for every failure that `@exortek/jws`
 * can raise. Branch on `code`, never on the message.
 */
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
export class JwsError extends Error {
  /**
   * @param {string} code    One of {@link ErrorCode}.
   * @param {string} message Human-readable diagnostic. Free-form; may
   *                         change across versions. Branch on `code`.
   * @param {{ cause?: unknown, status?: number }} [options]
   */
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'JwsError';
    this.code = code;
    this.status = options.status ?? statusFor(code);
  }
}

function statusFor(code) {
  switch (code) {
    case ErrorCode.INVALID_ARGUMENT:
    case ErrorCode.UNSUPPORTED_ALGORITHM:
    case ErrorCode.MISSING_ALG_ALLOWLIST:
      return 400;
    case ErrorCode.INVALID_TOKEN:
    case ErrorCode.INVALID_HEADER:
    case ErrorCode.INVALID_PAYLOAD:
    case ErrorCode.INVALID_SIGNATURE:
    case ErrorCode.INVALID_KEY:
    case ErrorCode.ALGORITHM_MISMATCH:
    case ErrorCode.ALGORITHM_NONE_FORBIDDEN:
    case ErrorCode.CRIT_UNSUPPORTED:
    case ErrorCode.KEY_NOT_FOUND:
      return 401;
    case ErrorCode.TOKEN_TOO_LARGE:
      return 413;
    default:
      return 500;
  }
}
