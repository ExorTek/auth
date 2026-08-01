/**
 * `@exortek/oauth2` — OAuth 2.1 for Node.js.
 *
 * The root entry exposes the security primitives every flow in this
 * package is built on: PKCE (RFC 7636), `state` / `nonce` CSRF nonces
 * (RFC 6749 §10.12, RFC 9700), and the error surface. The authorization
 * server (`./server`) and the provider presets (`./providers/*`) build
 * on these and ship in follow-up work.
 */
export { ErrorCode, OAuth2Error } from './internal/errors.js';
export { CODE_CHALLENGE_METHOD, createPkcePair, challengeFromVerifier, verifyChallenge } from './internal/pkce.js';
export { randomState, randomNonce } from './internal/state.js';
