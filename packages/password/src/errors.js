/**
 * Stable machine-readable codes for every failure that `@exortek/password`
 * can raise. Branch on `code`, never on the message text — messages are
 * free-form and change across versions.
 */
export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  INVALID_PASSWORD: 'INVALID_PASSWORD',
  INVALID_HASH: 'INVALID_HASH',
  UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM',
  UNSUPPORTED_PARAMS: 'UNSUPPORTED_PARAMS',
  MISSING_PEER_DEP: 'MISSING_PEER_DEP',
  PASSWORD_TOO_LONG: 'PASSWORD_TOO_LONG',
  PASSWORD_TOO_SHORT: 'PASSWORD_TOO_SHORT',
  POLICY_VIOLATION: 'POLICY_VIOLATION',
  BREACHED_PASSWORD: 'BREACHED_PASSWORD',
  REUSED_PASSWORD: 'REUSED_PASSWORD',
  HIBP_UNAVAILABLE: 'HIBP_UNAVAILABLE',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * {@link ErrorCode} `code` (branch on this) and a `status` — the HTTP
 * response status a middleware layer would use when translating the
 * error into a response.
 *
 * @example
 * try {
 *   await password.verify(input, storedHash)
 * } catch (err) {
 *   if (err instanceof PasswordError && err.code === ErrorCode.MISSING_PEER_DEP) {
 *     // stored hash was minted with an algo whose peer isn't installed
 *     logger.warn({ err }, 'install argon2 to verify legacy hashes')
 *   }
 *   throw err
 * }
 */
export class PasswordError extends Error {
  /**
   * @param {string} code    One of {@link ErrorCode}.
   * @param {string} message Human-readable diagnostic. Free-form; may
   *                         change across versions. Branch on `code`.
   * @param {{ cause?: unknown, status?: number, details?: Record<string, unknown> }} [options]
   */
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'PasswordError';
    this.code = code;
    this.status = options.status ?? statusFor(code);
    if (options.details) {
      this.details = options.details;
    }
  }
}

function statusFor(code) {
  switch (code) {
    case ErrorCode.INVALID_ARGUMENT:
    case ErrorCode.UNSUPPORTED_ALGORITHM:
    case ErrorCode.UNSUPPORTED_PARAMS:
    case ErrorCode.INVALID_HASH:
    case ErrorCode.PASSWORD_TOO_LONG:
    case ErrorCode.PASSWORD_TOO_SHORT:
    case ErrorCode.POLICY_VIOLATION:
      return 400;
    case ErrorCode.INVALID_PASSWORD:
      return 401;
    case ErrorCode.BREACHED_PASSWORD:
    case ErrorCode.REUSED_PASSWORD:
      return 422;
    case ErrorCode.MISSING_PEER_DEP:
    case ErrorCode.HIBP_UNAVAILABLE:
      return 500;
    default:
      return 500;
  }
}
