/**
 * `@exortek/oauth2` — OAuth 2.1 for Node.js.
 *
 * The root entry exposes the central `createOAuth` hub and the
 * `defineProvider` factory (for custom / self-hosted providers), plus
 * the security primitives every flow is built on: PKCE (RFC 7636),
 * `state` / `nonce` CSRF nonces (RFC 6749 §10.12, RFC 9700), and the
 * error surface. Provider presets are imported from `./providers/*`;
 * the authorization server (`./server`) ships in follow-up work.
 */
export { createOAuth } from './oauth.js';
export { defineProvider, WarningCode } from './providers/_base.js';
export { ErrorCode, OAuth2Error } from './internal/errors.js';
export { CODE_CHALLENGE_METHOD, createPkcePair, challengeFromVerifier, verifyChallenge } from './internal/pkce.js';
export { randomState, randomNonce } from './internal/state.js';
