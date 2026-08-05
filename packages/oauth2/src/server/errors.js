/**
 * Wire-protocol error catalogue for the authorization server.
 *
 * These are the OAuth 2.0 `error` values an authorization server returns
 * on the wire — the token-endpoint JSON body (RFC 6749 §5.2), the
 * authorization-endpoint redirect query (§4.1.2.1), and the extension
 * errors added by DPoP, the device grant, resource indicators, and token
 * exchange. They are deliberately DISTINCT from the library's own
 * {@link import('../internal/errors.js').ErrorCode} values (`STATE_MISMATCH`,
 * `ID_TOKEN_INVALID`, …) which describe RP-side callback validation. A
 * `ServerError.code` is the exact string that ships to the client.
 *
 * Rendering (JSON body vs. redirect query) lives in `response.js`; this
 * module only owns the vocabulary, the HTTP status mapping, and the
 * carried `error_description` / `error_uri` / `state`.
 */
import { BaseError } from '@exortek/shared/errors';

/**
 * Every OAuth 2.0 protocol `error` value this server can emit. Each is
 * thrown by the handler noted alongside it (no dead codes).
 */
export const ProtocolError = Object.freeze({
  // RFC 6749 — token + authorization endpoints.
  INVALID_REQUEST: 'invalid_request',
  INVALID_CLIENT: 'invalid_client',
  INVALID_GRANT: 'invalid_grant',
  UNAUTHORIZED_CLIENT: 'unauthorized_client',
  UNSUPPORTED_GRANT_TYPE: 'unsupported_grant_type',
  UNSUPPORTED_RESPONSE_TYPE: 'unsupported_response_type',
  INVALID_SCOPE: 'invalid_scope',
  ACCESS_DENIED: 'access_denied',
  SERVER_ERROR: 'server_error',
  TEMPORARILY_UNAVAILABLE: 'temporarily_unavailable',

  // RFC 7009 — revocation.
  UNSUPPORTED_TOKEN_TYPE: 'unsupported_token_type',

  // RFC 8707 — resource indicators / RFC 8693 — token exchange.
  INVALID_TARGET: 'invalid_target',

  // RFC 9396 — rich authorization requests.
  INVALID_AUTHORIZATION_DETAILS: 'invalid_authorization_details',

  // RFC 9449 — DPoP.
  INVALID_DPOP_PROOF: 'invalid_dpop_proof',
  USE_DPOP_NONCE: 'use_dpop_nonce',

  // RFC 8628 — device authorization grant (token-endpoint polling).
  AUTHORIZATION_PENDING: 'authorization_pending',
  SLOW_DOWN: 'slow_down',
  EXPIRED_TOKEN: 'expired_token',

  // RFC 7591 — dynamic client registration.
  INVALID_CLIENT_METADATA: 'invalid_client_metadata',
  INVALID_REDIRECT_URI: 'invalid_redirect_uri',
});

/**
 * A protocol-level failure destined for the client over the wire. The
 * `code` is the OAuth `error` value; the `message` becomes
 * `error_description`. `redirectable` marks errors that belong in an
 * authorization-endpoint redirect (so the caller echoes `state`), as
 * opposed to a direct token/introspection/revocation JSON response.
 *
 * `invalid_client` is `401` (the client failed to authenticate); every
 * other protocol error is `400`. The authorization-endpoint redirect
 * errors never surface as an HTTP status — they ride the `Location`
 * query — so their `400` only applies when there is no usable
 * `redirect_uri` to bounce back to (see `response.js`).
 */
export class ServerError extends BaseError {
  static statuses = {
    [ProtocolError.INVALID_CLIENT]: 401,
  };
  static defaultStatus = 400;

  /**
   * @param {string} code                       a {@link ProtocolError} value
   * @param {string} message                    human-readable `error_description`
   * @param {{ cause?: unknown, status?: number, redirectable?: boolean, errorUri?: string, state?: string, headers?: Record<string,string> }} [options]
   */
  constructor(code, message, options = {}) {
    super(code, message, options);
    /** @type {boolean} the error belongs in an authorize redirect, not a JSON body */
    this.redirectable = options.redirectable === true;
    if (options.errorUri !== undefined) {
      /** @type {string | undefined} RFC 6749 `error_uri` */
      this.errorUri = options.errorUri;
    }
    if (options.state !== undefined) {
      /** @type {string | undefined} `state` echoed on a redirect error */
      this.state = options.state;
    }
    if (options.headers !== undefined) {
      /** @type {Record<string,string> | undefined} extra response headers (e.g. `DPoP-Nonce`, `WWW-Authenticate`) */
      this.headers = options.headers;
    }
  }
}
