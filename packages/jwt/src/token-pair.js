/**
 * Access + refresh token pair with **reuse detection** — the killer
 * feature of this package. Refresh rotation follows RFC 6749 §10.4:
 * if the same refresh token is submitted twice outside the network-race
 * grace window, the entire family (all refresh tokens tied to that
 * user session) is revoked and `REFRESH_REUSED` raised.
 *
 * Subpath entry point (`@exortek/jwt/token-pair`).
 */

import { randomBytes } from 'node:crypto';

import { JwtError, ErrorCode } from './internal/errors.js';
import { parseDuration } from './internal/duration.js';
import { resolveHashFn, resolveEncoding, randomBuffer } from './internal/polymorphic.js';
import { sign } from './sign.js';

/**
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 * @typedef {import('./internal/memory-store.js').Store} Store
 * @typedef {import('./sign.js').SignOptions} SignOptions
 *
 * @typedef {Object} RefreshOptions
 * @property {string} alg                                                REQUIRED. Alg for signed refresh; unused when opaque:true.
 * @property {string | number} expiresIn                                 REQUIRED.
 * @property {boolean} [opaque]                                          Default true — random string. false → signed JWT refresh.
 * @property {number} [tokenSize]                                        Default 32 bytes.
 * @property {string} [encoding]                                         'base64url' | 'base64' | 'hex' | 'crockford' | 'uuid'.
 * @property {string} [hashAlgo]                                         Built-in: 'sha256' | 'sha384' | 'sha512'.
 * @property {(pt: string) => string | Promise<string>} [hashFn]         Custom override — wins over hashAlgo.
 * @property {() => Promise<{ plaintext: string, storeKey: string }>} [generate]  Custom generator — wins over hashFn.
 * @property {Store} store                                               REQUIRED.
 *
 * @typedef {Object} SecretPair
 * @property {KeyInput} access
 * @property {KeyInput} refresh
 *
 * @typedef {Object} CreateOptions
 * @property {SecretPair} secret
 * @property {SignOptions} access
 * @property {RefreshOptions} refresh
 * @property {string} [familyId]
 *
 * @typedef {Object} CreateResult
 * @property {string} accessToken
 * @property {string} refreshToken
 * @property {Date} accessExpiresAt
 * @property {Date} refreshExpiresAt
 * @property {string} familyId
 *
 * @typedef {Object} RotateOptions
 * @property {SecretPair} secret
 * @property {SignOptions} access
 * @property {RefreshOptions} refresh
 * @property {boolean} [detectReuse]                                     Default true.
 * @property {number | string} [reuseWindow]                             ms grace for network races. Default 0.
 * @property {Record<string, unknown>} [payload]                         Override stored payload for the new access token.
 *
 * @typedef {Object} RevokeOptions
 * @property {Store} store
 * @property {string} [hashAlgo]
 * @property {(pt: string) => string | Promise<string>} [hashFn]
 */

/**
 * @param {Record<string, unknown>} payload
 * @param {CreateOptions} options
 * @returns {Promise<CreateResult>}
 */
export async function create(payload, options) {
  _assertCreateOptions(options);
  const { secret, access, refresh } = options;
  const familyId = options.familyId || randomBytes(8).toString('hex');

  const now = Math.floor(Date.now() / 1000);
  const accessTtl = parseDuration(access.expiresIn ?? 0);
  const accessExpiresAtSec = now + Math.floor(accessTtl);
  const refreshTtl = parseDuration(refresh.expiresIn);
  const refreshExpiresAtSec = now + Math.floor(refreshTtl);

  const accessToken = await sign(payload, secret.access, access);
  const { plaintext: refreshPlaintext, storeKey: refreshStoreKey } = await _generateRefresh(
    refresh,
    payload,
    secret.refresh,
    refreshExpiresAtSec,
  );

  await refresh.store.add(refreshStoreKey, refreshExpiresAtSec, {
    familyId,
    payload,
    usedAt: null,
  });

  return {
    accessToken: typeof accessToken === 'string' ? accessToken : accessToken.token,
    refreshToken: refreshPlaintext,
    accessExpiresAt: new Date(accessExpiresAtSec * 1000),
    refreshExpiresAt: new Date(refreshExpiresAtSec * 1000),
    familyId,
  };
}

/**
 * Rotate a refresh token — issues a new access + refresh pair and
 * marks the old refresh as consumed. Second use of the same refresh
 * (outside the network-race grace window) triggers reuse detection:
 * the entire family (every refresh with the same `familyId`) is
 * revoked and `REFRESH_REUSED` raised.
 *
 * @param {string} oldRefreshToken
 * @param {RotateOptions} options
 * @returns {Promise<CreateResult>}
 */
export async function rotate(oldRefreshToken, options) {
  _assertCreateOptions(options);
  const { refresh } = options;
  const detectReuse = options.detectReuse !== false;
  const graceSec = options.reuseWindow !== undefined ? parseDuration(options.reuseWindow) : 0;

  const hashFn = resolveHashFn(refresh);
  const storeKey = await hashFn(oldRefreshToken);

  const record = await refresh.store.get(storeKey);
  if (!record) {
    throw new JwtError(
      ErrorCode.REVOKED,
      'rotate: refresh token is unknown or already revoked (family may have been invalidated)',
    );
  }

  const meta = record.metadata || {};
  const nowSec = Math.floor(Date.now() / 1000);

  if (typeof meta.usedAt === 'number') {
    const ageSec = nowSec - meta.usedAt;
    if (detectReuse && ageSec > graceSec) {
      // Reuse detected — revoke the whole family
      if (typeof meta.familyId === 'string') {
        await refresh.store.deleteAll({ familyId: meta.familyId });
      } else {
        await refresh.store.delete(storeKey);
      }
      throw new JwtError(
        ErrorCode.REFRESH_REUSED,
        `rotate: refresh token reuse detected (used ${ageSec}s ago, outside ${graceSec}s grace) — family revoked (RFC 6749 §10.4)`,
      );
    }
    // Inside grace window — network race, treat as idempotent replay.
    // Return the same shape as create(). The caller sees success.
  }

  // Mark old refresh as consumed but keep it in the store until its
  // native TTL runs out so a later reuse attempt can still be detected.
  await refresh.store.add(storeKey, record.expiresAt, { ...meta, usedAt: nowSec });

  const payload = /** @type {Record<string, unknown>} */ (options.payload || meta.payload || {});
  const familyId = typeof meta.familyId === 'string' ? meta.familyId : undefined;

  return create(payload, { ...options, familyId });
}

/**
 * @param {string} refreshToken
 * @param {RevokeOptions} options
 * @returns {Promise<void>}
 */
export async function revoke(refreshToken, options) {
  if (options == null || typeof options !== 'object' || options.store == null) {
    throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'revoke: options.store is required');
  }
  const hashFn = resolveHashFn(options);
  const storeKey = await hashFn(refreshToken);
  await options.store.delete(storeKey);
}

/**
 * @param {string} familyId
 * @param {{ store: Store }} options
 * @returns {Promise<number>}   count of revoked records
 */
export async function revokeAll(familyId, options) {
  if (options == null || typeof options !== 'object' || options.store == null) {
    throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'revokeAll: options.store is required');
  }
  if (typeof familyId !== 'string' || familyId.length === 0) {
    throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'revokeAll: familyId must be a non-empty string');
  }
  return options.store.deleteAll({ familyId });
}

/**
 * Bundled namespace matching the ARCHITECTURE example.
 */
export const tokenPair = Object.freeze({ create, rotate, revoke, revokeAll });

// ---------------------------------------------------------------------

/**
 * @param {CreateOptions | RotateOptions} options
 */
function _assertCreateOptions(options) {
  if (options == null || typeof options !== 'object') {
    throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'tokenPair: options object is required');
  }
  if (!options.secret || options.secret.access === undefined || options.secret.refresh === undefined) {
    throw new JwtError(
      ErrorCode.INVALID_ARGUMENT,
      'tokenPair: options.secret must be { access, refresh } (both required)',
    );
  }
  if (!options.access || typeof options.access.alg !== 'string') {
    throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'tokenPair: options.access.alg is required');
  }
  if (!options.refresh || typeof options.refresh.alg !== 'string') {
    throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'tokenPair: options.refresh.alg is required');
  }
  if (options.refresh.expiresIn === undefined) {
    throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'tokenPair: options.refresh.expiresIn is required');
  }
  if (options.refresh.store == null || typeof options.refresh.store.add !== 'function') {
    throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'tokenPair: options.refresh.store must implement the Store shape');
  }
}

/**
 * Produce `{ plaintext, storeKey }` for a refresh token. Custom
 * `refresh.generate` wins; otherwise we mint random bytes, encode
 * them, and hash them for storage.
 *
 * @param {RefreshOptions} refresh
 * @param {Record<string, unknown>} payload
 * @param {KeyInput} secret
 * @param {number} expiresAtSec
 * @returns {Promise<{ plaintext: string, storeKey: string }>}
 */
async function _generateRefresh(refresh, payload, secret, expiresAtSec) {
  if (typeof refresh.generate === 'function') {
    const result = await refresh.generate();
    if (result == null || typeof result.plaintext !== 'string' || typeof result.storeKey !== 'string') {
      throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'refresh.generate: must return { plaintext, storeKey } strings');
    }
    return result;
  }

  let plaintext;
  if (refresh.opaque === false) {
    // JWT refresh: sign a small payload containing the family reference
    const signed = await sign({ ...payload, kind: 'refresh' }, secret, {
      alg: refresh.alg,
      expiresIn: expiresAtSec - Math.floor(Date.now() / 1000),
    });
    plaintext = typeof signed === 'string' ? signed : signed.token;
  } else {
    const size = refresh.tokenSize ?? 32;
    if (typeof size !== 'number' || size < 1 || !Number.isFinite(size)) {
      throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'refresh.tokenSize must be a positive integer');
    }
    const encoder = resolveEncoding(refresh.encoding);
    plaintext = encoder(randomBuffer(size));
  }

  const hashFn = resolveHashFn(refresh);
  const storeKey = await hashFn(plaintext);
  return { plaintext, storeKey };
}
