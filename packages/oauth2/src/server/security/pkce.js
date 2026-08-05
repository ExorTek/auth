/**
 * Server-side PKCE (RFC 7636) — the authorization-server half. At the
 * authorization endpoint we validate that a client sent a well-formed
 * S256 `code_challenge`; at the token endpoint we recompute the challenge
 * from the presented `code_verifier` and compare it in constant time. The
 * transform + constant-time compare are already implemented once in
 * `internal/pkce.js`; this module reuses them so there is a single S256
 * codepath shared by the RP and the AS.
 *
 * `plain` is never accepted (OAuth 2.1 / Decision #0).
 */
import { isNonEmptyString } from '@exortek/shared/predicates';

import { verifyChallenge, CODE_CHALLENGE_METHOD } from '../../internal/pkce.js';
import { ProtocolError, ServerError } from '../errors.js';

// RFC 7636 §4.1: 43–128 chars from the unreserved set.
const VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;
// A base64url SHA-256 digest is exactly 43 chars, unpadded.
const CHALLENGE_RE = /^[A-Za-z0-9\-_]{43}$/;

/**
 * Validate the PKCE parameters on an authorization request and return the
 * challenge to bind to the authorization code.
 *
 * @param {Record<string, any>} params
 * @param {{ required: boolean, redirectableState?: string }} options
 * @returns {{ codeChallenge: string }}
 */
export function resolvePkceChallenge(params, options) {
  const challenge = params.code_challenge;
  const method = params.code_challenge_method;
  const opts = { redirectable: true, state: options.redirectableState };

  if (!isNonEmptyString(challenge)) {
    if (options.required) {
      throw new ServerError(ProtocolError.INVALID_REQUEST, 'code_challenge is required (PKCE)', opts);
    }
    return { codeChallenge: '' };
  }
  // `plain` and any non-S256 method are refused outright.
  if (isNonEmptyString(method) && method !== CODE_CHALLENGE_METHOD) {
    throw new ServerError(
      ProtocolError.INVALID_REQUEST,
      `unsupported code_challenge_method ${JSON.stringify(method)}; only S256 is allowed`,
      opts,
    );
  }
  if (!isNonEmptyString(method)) {
    // RFC 7636 defaults an absent method to `plain` — which we reject, so
    // require the client to name S256 explicitly.
    throw new ServerError(ProtocolError.INVALID_REQUEST, 'code_challenge_method must be S256', opts);
  }
  if (!CHALLENGE_RE.test(challenge)) {
    throw new ServerError(ProtocolError.INVALID_REQUEST, 'malformed S256 code_challenge', opts);
  }
  return { codeChallenge: challenge };
}

/**
 * Verify a presented `code_verifier` against the bound challenge at the
 * token endpoint. Throws `invalid_grant` on any mismatch (RFC 7636 §4.6).
 *
 * @param {string | undefined} codeVerifier
 * @param {string} boundChallenge   the challenge stored with the auth code (empty = none was bound)
 */
export function verifyCodeVerifier(codeVerifier, boundChallenge) {
  const hadChallenge = isNonEmptyString(boundChallenge);
  if (!hadChallenge) {
    // No challenge was bound (a provider genuinely without PKCE). Nothing
    // to verify; the loud warning was emitted at the authorize step.
    return;
  }
  if (!isNonEmptyString(codeVerifier) || !VERIFIER_RE.test(codeVerifier)) {
    throw new ServerError(ProtocolError.INVALID_GRANT, 'missing or malformed code_verifier');
  }
  if (!verifyChallenge(codeVerifier, boundChallenge)) {
    throw new ServerError(ProtocolError.INVALID_GRANT, 'code_verifier does not match the code_challenge');
  }
}
