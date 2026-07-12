/**
 * Stable machine-readable codes for every failure that `@exortek/otp`
 * can raise. Branch on `code`, never on the message.
 */
export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  INVALID_SECRET: 'INVALID_SECRET',
  INVALID_CODE: 'INVALID_CODE',
  THROTTLED: 'THROTTLED',
  REPLAY_DETECTED: 'REPLAY_DETECTED',
  UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * `code` (from {@link ErrorCode}) and a `status` — the HTTP response
 * status a middleware layer would use when translating the error.
 */
export class OtpError extends Error {
  /**
   * @param {string} code    One of {@link ErrorCode}.
   * @param {string} message Human-readable diagnostic. Free-form; may
   *                         change across versions. Branch on `code`.
   * @param {{ cause?: unknown, status?: number }} [options]
   */
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'OtpError';
    this.code = code;
    this.status = options.status ?? statusFor(code);
  }
}

function statusFor(code) {
  switch (code) {
    case ErrorCode.INVALID_ARGUMENT:
    case ErrorCode.UNSUPPORTED_ALGORITHM:
      return 400;
    case ErrorCode.INVALID_SECRET:
    case ErrorCode.INVALID_CODE:
      return 401;
    case ErrorCode.REPLAY_DETECTED:
      return 403;
    case ErrorCode.THROTTLED:
      return 429;
    default:
      return 500;
  }
}
