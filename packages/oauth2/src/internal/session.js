/**
 * The authorization-flow session — the opaque bundle `authorize()`
 * hands back for the caller to stash (in a cookie / server store) and
 * hand to `callback()`. It carries everything the callback needs to
 * validate the round-trip: the `state` CSRF nonce, the PKCE
 * `code_verifier`, the OIDC `nonce`, the provider context, and an
 * optional caller session binding.
 *
 * `serialize` / `deserialize` are the single contract every storage
 * mode goes through. Today that is JSON rendered base64url so it rides
 * a cookie unescaped; a future `@exortek/jwe` seal swaps in behind
 * exactly this contract with no change to callers.
 */
import { encode as base64urlEncode, decode as base64urlDecode } from '@exortek/shared/base64url';
import { isNonEmptyString, isObject } from '@exortek/shared/predicates';

import { ErrorCode, OAuth2Error } from './errors.js';

/**
 * @typedef {Object} FlowSession
 * @property {string} provider          the provider id the flow was started for
 * @property {string} state             CSRF nonce echoed on the callback
 * @property {string} [codeVerifier]    PKCE verifier (absent only when the provider rejects PKCE)
 * @property {string} [nonce]           OIDC replay nonce (OIDC providers only)
 * @property {string} [sessionBinding]  opaque binding to the initiating user's session
 * @property {string[]} [requestedScope] the scopes this flow requested — basis for the SCOPE_NARROWED warning
 * @property {number} createdAt         epoch ms — lets a store enforce a max age
 */

/**
 * @param {FlowSession} session
 * @returns {string}
 */
export function serializeSession(session) {
  return base64urlEncode(Buffer.from(JSON.stringify(session), 'utf8'));
}

/**
 * @param {string} serialized
 * @returns {FlowSession}
 */
export function deserializeSession(serialized) {
  if (!isNonEmptyString(serialized)) {
    throw new OAuth2Error(ErrorCode.MISSING_STATE, 'no flow session was provided to callback()');
  }

  /** @type {unknown} */
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(base64urlDecode(serialized)).toString('utf8'));
  } catch {
    throw new OAuth2Error(ErrorCode.MISSING_STATE, 'flow session is malformed or was tampered with');
  }

  if (!isObject(parsed) || !isNonEmptyString(parsed.state) || !isNonEmptyString(parsed.provider)) {
    throw new OAuth2Error(ErrorCode.MISSING_STATE, 'flow session is missing its `state` / `provider` binding');
  }

  return /** @type {FlowSession} */ (parsed);
}
