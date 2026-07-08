export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  CSRF_MISSING: 'CSRF_MISSING',
  CSRF_MISMATCH: 'CSRF_MISMATCH',
  CSRF_MALFORMED: 'CSRF_MALFORMED',
  CSRF_TAMPERED: 'CSRF_TAMPERED',
  RATE_LIMITED: 'RATE_LIMITED',
  ORIGIN_DENIED: 'ORIGIN_DENIED',
  REDIRECT_UNSAFE: 'REDIRECT_UNSAFE',
  PATH_TRAVERSAL: 'PATH_TRAVERSAL',
  BODY_TOO_LARGE: 'BODY_TOO_LARGE',
  REQUEST_TIMEOUT: 'REQUEST_TIMEOUT',
  WEBHOOK_INVALID: 'WEBHOOK_INVALID',
  HONEYPOT_TRIGGERED: 'HONEYPOT_TRIGGERED',
});

export class SecurityError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {number} [status=400]
   */
  constructor(code, message, status = 400) {
    super(message);
    this.name = 'SecurityError';
    this.code = code;
    this.status = status;
  }
}
