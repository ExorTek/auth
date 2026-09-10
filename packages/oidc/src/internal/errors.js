/**
 * Stable machine-readable codes for every failure that `@exortek/oidc`
 * can raise. Branch on `code`, never on the message.
 *
 * These are the library's own error codes — distinct from the OpenID
 * Connect protocol `error` values an OpenID Provider returns on the wire.
 * The protocol catalogue lands with the provider/client flow handlers.
 */
import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  // Configuration / argument guards raised by `createClient` / `createProvider`.
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',

  // Reserved while the flow handlers are scaffolded. Every method exposed on
  // the returned client/provider throws this until its real implementation
  // lands, so a consumer wiring the package up early gets an actionable code
  // instead of an undefined-is-not-a-function crash.
  NOT_IMPLEMENTED: 'NOT_IMPLEMENTED',
});

/**
 * Every recoverable failure raised by this package. Carries a stable `code`
 * (from {@link ErrorCode}) and, via the {@link OidcError.statuses} map, the
 * HTTP `status` a middleware layer maps it to.
 *
 * @augments BaseError
 */
export class OidcError extends BaseError {
  static statuses = {
    INVALID_ARGUMENT: 400,
    NOT_IMPLEMENTED: 501,
  };

  static defaultStatus = 500;
}

/**
 * Guard helper — throw a configuration error with a consistent shape.
 *
 * @param {string} message
 * @returns {never}
 */
export function invalidArgument(message) {
  throw new OidcError(ErrorCode.INVALID_ARGUMENT, message);
}

/**
 * Placeholder thrown by every scaffolded flow method until it is implemented.
 *
 * @param {string} what  The operation that is not yet available.
 * @returns {never}
 */
export function notImplemented(what) {
  throw new OidcError(
    ErrorCode.NOT_IMPLEMENTED,
    `${what} is not implemented yet — @exortek/oidc is pre-release (0.0.0).`,
  );
}
