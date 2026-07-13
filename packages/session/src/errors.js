/**
 * Stable machine-readable codes for every failure that
 * `@exortek/session` can raise. Branch on `code`, never on the message
 * text — messages are free-form and change across versions.
 */
export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',

  // Token / cookie problems
  MISSING_TOKEN: 'MISSING_TOKEN',
  INVALID_TOKEN: 'INVALID_TOKEN',
  EXPIRED: 'EXPIRED',
  IDLE_TIMEOUT: 'IDLE_TIMEOUT',

  // Store state
  REVOKED: 'REVOKED',
  SESSION_NOT_FOUND: 'SESSION_NOT_FOUND',
  TOKEN_ROTATION_REQUIRED: 'TOKEN_ROTATION_REQUIRED',

  // Bindings
  FINGERPRINT_MISMATCH: 'FINGERPRINT_MISMATCH',
  SUSPICIOUS_ACTIVITY: 'SUSPICIOUS_ACTIVITY',

  // Policy
  CONCURRENT_LIMIT_EXCEEDED: 'CONCURRENT_LIMIT_EXCEEDED',
  FRESH_AUTH_REQUIRED: 'FRESH_AUTH_REQUIRED',
  IMPERSONATION_INVALID: 'IMPERSONATION_INVALID',

  // Infra
  MISSING_PEER_DEP: 'MISSING_PEER_DEP',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * {@link ErrorCode} `code` (branch on this) and a `status` — the HTTP
 * response status a middleware layer would use when translating the
 * error into a response.
 *
 * @example
 * try {
 *   const session = await sessions.verify(req)
 * } catch (err) {
 *   if (err instanceof SessionError) {
 *     if (err.code === ErrorCode.FRESH_AUTH_REQUIRED) return res.redirect('/reauth')
 *     if (err.code === ErrorCode.EXPIRED)             return res.redirect('/login?expired=1')
 *   }
 *   throw err
 * }
 */
export class SessionError extends Error {
  /**
   * @param {string} code    One of {@link ErrorCode}.
   * @param {string} message Human-readable diagnostic. Free-form; may
   *                         change across versions. Branch on `code`.
   * @param {{ cause?: unknown, status?: number, details?: Record<string, unknown> }} [options]
   */
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'SessionError';
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
      return 400;
    case ErrorCode.MISSING_TOKEN:
    case ErrorCode.INVALID_TOKEN:
    case ErrorCode.EXPIRED:
    case ErrorCode.IDLE_TIMEOUT:
    case ErrorCode.REVOKED:
    case ErrorCode.SESSION_NOT_FOUND:
    case ErrorCode.TOKEN_ROTATION_REQUIRED:
    case ErrorCode.FINGERPRINT_MISMATCH:
    case ErrorCode.SUSPICIOUS_ACTIVITY:
    case ErrorCode.CONCURRENT_LIMIT_EXCEEDED:
    case ErrorCode.FRESH_AUTH_REQUIRED:
      return 401;
    case ErrorCode.IMPERSONATION_INVALID:
      return 403;
    case ErrorCode.MISSING_PEER_DEP:
      return 500;
    default:
      return 500;
  }
}
