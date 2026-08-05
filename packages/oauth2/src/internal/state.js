/**
 * CSRF / replay nonces for the authorization-code flow.
 *
 * `state` binds the authorization request to the user's session and is
 * checked on the callback (RFC 6749 §10.12, OAuth 2.0 Security BCP
 * RFC 9700). `nonce` is the OpenID Connect replay guard, echoed in the
 * ID token. Both are just CSPRNG bytes rendered base64url — kept in one
 * place so every flow reaches for the same generator instead of
 * re-inventing it.
 */
import { encode as base64urlEncode } from '@exortek/shared/base64url';
import { randomBuffer } from '@exortek/shared/random';

import { requireIntegerAtLeast } from './guards.js';

const DEFAULT_BYTES = 32;

/**
 * @param {number} [bytes]  entropy in bytes (default 32 → 256 bits)
 * @returns {string} base64url-encoded random value
 */
export function randomState(bytes = DEFAULT_BYTES) {
  requireIntegerAtLeast(bytes, 'bytes', 16);
  return base64urlEncode(randomBuffer(bytes));
}

/**
 * @param {number} [bytes]  entropy in bytes (default 32 → 256 bits)
 * @returns {string} base64url-encoded random value
 */
export function randomNonce(bytes = DEFAULT_BYTES) {
  requireIntegerAtLeast(bytes, 'bytes', 16);
  return base64urlEncode(randomBuffer(bytes));
}
