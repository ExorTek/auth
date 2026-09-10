/**
 * Stable machine-readable codes for every failure that `@exortek/oidc`
 * can raise. Branch on `code`, never on the message.
 *
 * These are the library's own error codes — distinct from the OpenID
 * Connect protocol `error` values an OpenID Provider returns on the wire.
 * The client flow delegates to `@exortek/oauth2`, so callback-validation
 * failures surface as `OAuth2Error` and are left to propagate.
 */
import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  // Configuration / argument guards raised by `createClient` / `createProvider`
  // and the provider handlers.
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
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
