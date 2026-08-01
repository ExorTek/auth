/**
 * Stable machine-readable codes for every failure that `@exortek/oauth2`
 * can raise. Branch on `code`, never on the message.
 *
 * These are the library's own error codes — distinct from the OAuth 2.0
 * protocol `error` values (`invalid_request`, `invalid_grant`, …) that
 * an authorization server returns on the wire. The protocol catalogue
 * lands with the server/client flow handlers.
 */
import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * `code` (from {@link ErrorCode}) and a `status` — the HTTP response
 * status a middleware layer would use when translating the error.
 */
export class OAuth2Error extends BaseError {
  static statuses = {
    [ErrorCode.INVALID_ARGUMENT]: 400,
  };
  static defaultStatus = 500;
}
