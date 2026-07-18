/**
 * Shared base error class — the single error structure behind every
 * `@exortek/*` package's `errors.js`.
 *
 * Every package keeps its own class identity with a one-liner subclass;
 * codes stay per-package frozen maps, status mapping is declared as a
 * static field:
 *
 *   import { BaseError } from '@exortek/shared/errors';
 *
 *   export const ErrorCode = Object.freeze({
 *     INVALID_ARGUMENT: 'INVALID_ARGUMENT',
 *     INVALID_TOKEN: 'INVALID_TOKEN',
 *   });
 *
 *   export class JwtError extends BaseError {
 *     static statuses = { INVALID_ARGUMENT: 400, INVALID_TOKEN: 401 };
 *     static defaultStatus = 500;
 *   }
 *
 * Instances carry a stable machine-readable `code` (branch on this,
 * never on the message), an optional HTTP `status`, an optional
 * `details` object, and the standard `cause` chain.
 */
export class BaseError extends Error {
  /**
   * Optional `code → HTTP status` map declared on the subclass. When
   * absent the instance carries no `status` at all — for HTTP-agnostic
   * packages like `@exortek/crypto`.
   *
   * @type {Record<string, number> | undefined}
   */
  static statuses = undefined;

  /**
   * Fallback status for codes missing from `statuses`.
   *
   * @type {number}
   */
  static defaultStatus = 500;

  /**
   * @param {string} code    Stable machine-readable code; branch on this.
   * @param {string} message Human-readable diagnostic. Free-form; may
   *                         change across versions.
   * @param {{ cause?: unknown, status?: number, details?: Record<string, unknown> }} [options]
   */
  constructor(code, message, options = {}) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = new.target.name;
    /** @type {string} */
    this.code = code;
    const statuses = /** @type {typeof BaseError} */ (new.target).statuses;
    if (options.status !== undefined) {
      /** @type {number | undefined} */
      this.status = options.status;
    } else if (statuses !== undefined) {
      // Object.hasOwn guards against inherited-property lookups for
      // exotic code values ('toString', 'constructor', …).
      this.status = Object.hasOwn(statuses, code)
        ? statuses[code]
        : /** @type {typeof BaseError} */ (new.target).defaultStatus;
    }
    if (options.details) {
      /** @type {Record<string, unknown> | undefined} */
      this.details = options.details;
    }
  }
}
