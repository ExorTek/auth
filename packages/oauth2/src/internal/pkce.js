/**
 * PKCE — Proof Key for Code Exchange (RFC 7636).
 *
 * Only the `S256` challenge method is implemented. `plain` is
 * deliberately unsupported: OAuth 2.1 requires `S256` for any client
 * that can compute a SHA-256, and a `plain` challenge offers no
 * protection against an attacker who can read the authorization
 * request. See [[project_design_philosophy]] — the safe path is the
 * only path.
 */
import { createHash } from 'node:crypto';

import { encode as base64urlEncode } from '@exortek/shared/base64url';
import { randomBuffer } from '@exortek/shared/random';
import { timingSafeEqual } from '@exortek/shared/timing-safe';

import { requireNonEmptyString } from './guards.js';

export const CODE_CHALLENGE_METHOD = 'S256';

// RFC 7636 §4.1: the verifier is 43–128 chars from the unreserved set.
// A base64url-encoded 32-byte random value is 43 chars — the shortest
// value the spec allows, and 256 bits of entropy.
const VERIFIER_BYTES = 32;

/**
 * The `S256` transform: `BASE64URL(SHA256(ASCII(code_verifier)))`.
 *
 * @param {string} codeVerifier
 * @returns {string} the `code_challenge`
 */
export function challengeFromVerifier(codeVerifier) {
  requireNonEmptyString(codeVerifier, 'codeVerifier');
  return base64urlEncode(createHash('sha256').update(codeVerifier, 'ascii').digest());
}

/**
 * @typedef {Object} PkcePair
 * @property {string} codeVerifier         keep server-side; send at token exchange
 * @property {string} codeChallenge        send on the authorization request
 * @property {'S256'} codeChallengeMethod
 */

/**
 * Generate a fresh `code_verifier` / `code_challenge` pair.
 *
 * @returns {PkcePair}
 */
export function createPkcePair() {
  const codeVerifier = base64urlEncode(randomBuffer(VERIFIER_BYTES));
  return {
    codeVerifier,
    codeChallenge: challengeFromVerifier(codeVerifier),
    codeChallengeMethod: CODE_CHALLENGE_METHOD,
  };
}

/**
 * Recompute the challenge from a presented verifier and compare it,
 * in constant time, against the one bound to the authorization request.
 * The authorization server calls this at the token endpoint.
 *
 * @param {string} codeVerifier   presented by the client at token exchange
 * @param {string} codeChallenge  bound to the authorization code
 * @returns {boolean}
 */
export function verifyChallenge(codeVerifier, codeChallenge) {
  requireNonEmptyString(codeChallenge, 'codeChallenge');
  // Both operands are ASCII base64url; compare as bytes in constant time.
  return timingSafeEqual(
    Buffer.from(challengeFromVerifier(codeVerifier), 'ascii'),
    Buffer.from(codeChallenge, 'ascii'),
  );
}
