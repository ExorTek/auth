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
  // Configuration / argument guards.
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',

  // Callback validation (OAuth 2.0 Security BCP, RFC 9700). Each is thrown by
  // the flow step that detects the corresponding attack.
  MISSING_STATE: 'MISSING_STATE',
  STATE_MISMATCH: 'STATE_MISMATCH',
  ISSUER_MISMATCH: 'ISSUER_MISMATCH',
  NONCE_MISMATCH: 'NONCE_MISMATCH',
  SUB_MISMATCH: 'SUB_MISMATCH',
  AUDIENCE_MISMATCH: 'AUDIENCE_MISMATCH',
  ID_TOKEN_INVALID: 'ID_TOKEN_INVALID',
  CONTEXT_MISMATCH: 'CONTEXT_MISMATCH',
  SESSION_MISMATCH: 'SESSION_MISMATCH',

  // The provider returned `error=...` on the callback (e.g. access_denied).
  PROVIDER_ERROR: 'PROVIDER_ERROR',

  // Talking to the provider's endpoints.
  TOKEN_EXCHANGE_FAILED: 'TOKEN_EXCHANGE_FAILED',
  USERINFO_FAILED: 'USERINFO_FAILED',
  DISCOVERY_FAILED: 'DISCOVERY_FAILED',
  NETWORK_ERROR: 'NETWORK_ERROR',
});

/**
 * Every recoverable failure raised by this package. Carries a stable
 * `code` (from {@link ErrorCode}) and a `status` — the HTTP response
 * status a middleware layer would use when translating the error.
 *
 * Callback-validation failures map to `400` (the request that reached us
 * is malformed / forged); failures talking to the provider map to `502`
 * (an upstream we depend on misbehaved).
 */
export class OAuth2Error extends BaseError {
  static statuses = {
    [ErrorCode.INVALID_ARGUMENT]: 400,
    [ErrorCode.MISSING_STATE]: 400,
    [ErrorCode.STATE_MISMATCH]: 400,
    [ErrorCode.ISSUER_MISMATCH]: 400,
    [ErrorCode.NONCE_MISMATCH]: 400,
    [ErrorCode.SUB_MISMATCH]: 400,
    [ErrorCode.AUDIENCE_MISMATCH]: 400,
    [ErrorCode.ID_TOKEN_INVALID]: 400,
    [ErrorCode.CONTEXT_MISMATCH]: 400,
    [ErrorCode.SESSION_MISMATCH]: 400,
    [ErrorCode.PROVIDER_ERROR]: 400,
    [ErrorCode.TOKEN_EXCHANGE_FAILED]: 502,
    [ErrorCode.USERINFO_FAILED]: 502,
    [ErrorCode.DISCOVERY_FAILED]: 502,
    [ErrorCode.NETWORK_ERROR]: 502,
  };
  static defaultStatus = 500;
}
