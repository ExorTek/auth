/**
 * Access + refresh token pair with **reuse detection** — the killer
 * feature of this package. Refresh rotation follows RFC 6749 §10.4:
 * if the same refresh token is submitted twice outside the network-race
 * grace window, the entire family (all refresh tokens tied to that
 * user session) is revoked and `REFRESH_REUSED` raised.
 *
 * Subpath entry point (`@exortek/jwt/token-pair`). Scaffold stub.
 */

import { JwtError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 * @typedef {import('./internal/memory-store.js').Store} Store
 * @typedef {import('./sign.js').SignOptions} SignOptions
 *
 * @typedef {Object} RefreshOptions
 * @property {string} alg
 * @property {string | number} expiresIn
 * @property {boolean} [opaque]
 * @property {number} [tokenSize]
 * @property {string} [encoding]                                          Built-in shortcut.
 * @property {string} [hashAlgo]                                          Built-in shortcut.
 * @property {(pt: string) => string | Promise<string>} [hashFn]          Custom override.
 * @property {() => Promise<{ plaintext: string, storeKey: string }>} [generate]
 * @property {Store} store
 * @property {string} [familyId]
 * @property {number} [reuseWindow]  ms grace for network races.
 *
 * @typedef {Object} CreateOptions
 * @property {{ access: KeyInput, refresh: KeyInput }} secret
 * @property {SignOptions} access
 * @property {RefreshOptions} refresh
 *
 * @typedef {Object} CreateResult
 * @property {string} accessToken
 * @property {string} refreshToken
 * @property {Date} accessExpiresAt
 * @property {Date} refreshExpiresAt
 * @property {string} familyId
 */

/**
 * @param {Record<string, unknown>} _payload
 * @param {CreateOptions} _options
 * @returns {Promise<CreateResult>}
 */
export async function create(_payload, _options) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'tokenPair.create: not implemented');
}

/**
 * @param {string} _oldRefreshToken
 * @param {CreateOptions & { detectReuse?: boolean }} _options
 * @returns {Promise<CreateResult>}
 */
export async function rotate(_oldRefreshToken, _options) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'tokenPair.rotate: not implemented');
}

/**
 * @param {string} _refreshToken
 * @param {{ store: Store, hashFn?: (pt: string) => string | Promise<string>, hashAlgo?: string }} _options
 * @returns {Promise<void>}
 */
export async function revoke(_refreshToken, _options) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'tokenPair.revoke: not implemented');
}

/**
 * @param {string} _familyId
 * @param {{ store: Store }} _options
 * @returns {Promise<number>}   count of revoked entries
 */
export async function revokeAll(_familyId, _options) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'tokenPair.revokeAll: not implemented');
}

/**
 * Namespace object mirroring the ARCHITECTURE example.
 */
export const tokenPair = Object.freeze({ create, rotate, revoke, revokeAll });
