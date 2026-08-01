/**
 * Access + refresh token pair with **reuse detection** — the same
 * rotation-safety story `@exortek/jwt` ships, on PASETO tokens. Refresh
 * rotation follows RFC 6749 §10.4: if a refresh token is submitted twice
 * outside the network-race grace window, the whole family (every refresh
 * tied to that session) is revoked and `REFRESH_REUSED` raised.
 *
 * The access token's purpose is the caller's choice — `access.purpose`
 * is `'local'` (v4.local, encrypted; the default and safest for tokens
 * your own services read) or `'public'` (v4.public, signed; when a
 * separate relying party must verify it).
 */

import { randomBytes } from 'node:crypto';

import { isFunction, isNumber, isString, isInteger, isNullish } from '@exortek/shared/predicates';

import { PasetoError, ErrorCode } from './internal/errors.js';
import { assertNonEmptyString, assertObject, invalidArgument } from './internal/guards.js';
import { parseDurationSeconds } from './internal/duration.js';
import { resolveHashFn, resolveEncoding, randomBuffer } from './internal/polymorphic.js';
import { createKeyMutex } from './internal/mutex.js';
import { encrypt } from './local.js';
import { sign } from './public.js';

// Fallback for stores without atomic markUsed — serialises the
// get→check→add sequence in-process so two concurrent rotate calls for
// the same key don't both observe usedAt:null.
const _rotateLock = createKeyMutex();

/**
 * @typedef {import('./internal/memory-store.js').Store} Store
 *
 * @typedef {Object} AccessOptions
 * @property {'local' | 'public'} [purpose='local']   token purpose
 * @property {string | number} expiresIn              REQUIRED.
 * @property {string} [issuer]
 * @property {string} [subject]
 * @property {string} [audience]
 * @property {Record<string, unknown> | string} [footer]
 * @property {string | Uint8Array} [assertion]
 *
 * @typedef {Object} RefreshOptions
 * @property {string | number} expiresIn              REQUIRED.
 * @property {boolean} [opaque=true]                  false → a signed/encrypted PASETO refresh.
 * @property {'local' | 'public'} [purpose='local']   purpose when opaque:false.
 * @property {number} [tokenSize=32]                  opaque token byte length.
 * @property {string} [encoding='base64url']          'base64url' | 'base64' | 'hex' | 'crockford' | 'uuid'.
 * @property {string} [hashAlgo='sha256']             'sha256' | 'sha384' | 'sha512'.
 * @property {(pt: string) => string | Promise<string>} [hashFn]
 * @property {() => Promise<{ plaintext: string, storeKey: string }>} [generate]
 * @property {Store} store                            REQUIRED.
 *
 * @typedef {Object} SecretPair
 * @property {Uint8Array | import('node:crypto').KeyObject} access
 * @property {Uint8Array | import('node:crypto').KeyObject} [refresh]
 *
 * @typedef {Object} CreateOptions
 * @property {SecretPair} secret
 * @property {AccessOptions} access
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
 * @property {AccessOptions} access
 * @property {RefreshOptions} refresh
 * @property {boolean} [detectReuse=true]
 * @property {number | string} [reuseWindow=0]        grace for network races
 * @property {Record<string, unknown>} [payload]      override stored payload
 */

/** Mint the access token in the requested purpose. */
function mintAccess(payload, secret, access) {
  const { purpose = 'local', ...opts } = access;
  if (purpose === 'public') {
    return sign(payload, secret, opts);
  }
  if (purpose === 'local') {
    return encrypt(payload, secret, opts);
  }
  throw invalidArgument(`access.purpose must be 'local' or 'public', got ${JSON.stringify(purpose)}`);
}

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
  const accessExpiresAtSec = now + Math.floor(parseDurationSeconds(access.expiresIn));
  const refreshExpiresAtSec = now + Math.floor(parseDurationSeconds(refresh.expiresIn));

  const accessToken = mintAccess(payload, secret.access, access);
  const { plaintext: refreshPlaintext, storeKey: refreshStoreKey } = await _generateRefresh(
    refresh,
    payload,
    secret.refresh,
    refreshExpiresAtSec,
  );

  await refresh.store.add(refreshStoreKey, refreshExpiresAtSec, { familyId, payload, usedAt: null });

  return {
    accessToken,
    refreshToken: refreshPlaintext,
    accessExpiresAt: new Date(accessExpiresAtSec * 1000),
    refreshExpiresAt: new Date(refreshExpiresAtSec * 1000),
    familyId,
  };
}

/**
 * Rotate a refresh token — issue a fresh pair and consume the old
 * refresh. A second use of the same refresh (outside the grace window)
 * revokes the whole family and raises `REFRESH_REUSED` (RFC 6749 §10.4).
 * Concurrent rotations of the same token are serialised — via the store's
 * atomic `markUsed` (CAS / Lua) when available, else an in-process mutex.
 *
 * @param {string} oldRefreshToken
 * @param {RotateOptions} options
 * @returns {Promise<CreateResult>}
 */
export async function rotate(oldRefreshToken, options) {
  _assertCreateOptions(options);
  const { refresh } = options;
  const detectReuse = options.detectReuse !== false;
  const graceSec = options.reuseWindow !== undefined ? parseDurationSeconds(options.reuseWindow) : 0;

  const hashFn = resolveHashFn(refresh);
  const storeKey = await hashFn(oldRefreshToken);
  const hasAtomicMarkUsed = isFunction(refresh.store.markUsed);

  const doRotate = async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    let record;
    let isReplay;

    if (hasAtomicMarkUsed) {
      const cas = await refresh.store.markUsed(storeKey, nowSec);
      if (!cas) {
        throw new PasetoError(
          ErrorCode.REVOKED,
          'rotate: refresh token is unknown or already revoked (family may have been invalidated)',
        );
      }
      record = cas.record;
      isReplay = !cas.swapped;
    } else {
      record = await refresh.store.get(storeKey);
      if (!record) {
        throw new PasetoError(
          ErrorCode.REVOKED,
          'rotate: refresh token is unknown or already revoked (family may have been invalidated)',
        );
      }
      const meta = record.metadata || {};
      isReplay = isNumber(meta.usedAt);
      if (!isReplay) {
        await refresh.store.add(storeKey, record.expiresAt, { ...meta, usedAt: nowSec });
      }
    }

    const meta = record.metadata || {};

    if (isReplay) {
      const ageSec = nowSec - meta.usedAt;
      const outsideGrace = graceSec === 0 ? true : ageSec > graceSec;
      if (detectReuse && outsideGrace) {
        if (isString(meta.familyId)) {
          await refresh.store.deleteAll({ familyId: meta.familyId });
        } else {
          await refresh.store.delete(storeKey);
        }
        throw new PasetoError(
          ErrorCode.REFRESH_REUSED,
          `rotate: refresh token reuse detected (used ${ageSec}s ago, outside ${graceSec}s grace) — family revoked (RFC 6749 §10.4)`,
        );
      }
    }

    const payload = /** @type {Record<string, unknown>} */ (options.payload || meta.payload || {});
    const familyId = isString(meta.familyId) ? meta.familyId : undefined;

    return create(payload, { ...options, familyId });
  };

  if (hasAtomicMarkUsed) {
    return doRotate();
  }
  return _rotateLock.withLock(storeKey, doRotate);
}

/**
 * @param {string} refreshToken
 * @param {{ store: Store, hashAlgo?: string, hashFn?: (pt: string) => string | Promise<string> }} options
 * @returns {Promise<void>}
 */
export async function revoke(refreshToken, options) {
  assertObject(options, 'revoke.options');
  if (options.store == null) {
    throw invalidArgument('revoke.options.store is required');
  }
  const hashFn = resolveHashFn(options);
  const storeKey = await hashFn(refreshToken);
  await options.store.delete(storeKey);
}

/**
 * @param {string} familyId
 * @param {{ store: Store }} options
 * @returns {Promise<number>} count of revoked records
 */
export async function revokeAll(familyId, options) {
  assertObject(options, 'revokeAll.options');
  if (options.store == null) {
    throw invalidArgument('revokeAll.options.store is required');
  }
  assertNonEmptyString(familyId, 'revokeAll.familyId');
  return options.store.deleteAll({ familyId });
}

/**
 * Bundled namespace matching the ARCHITECTURE example.
 */
export const tokenPair = Object.freeze({ create, rotate, revoke, revokeAll });

/** @param {CreateOptions | RotateOptions} options */
function _assertCreateOptions(options) {
  assertObject(options, 'tokenPair.options');
  if (!options.secret || options.secret.access === undefined) {
    throw invalidArgument('tokenPair.options.secret must be { access, refresh? } (access required)');
  }
  if (!options.access || options.access.expiresIn === undefined) {
    throw invalidArgument('tokenPair.options.access.expiresIn is required');
  }
  if (!options.refresh) {
    throw invalidArgument('tokenPair.options.refresh is required');
  }
  if (options.refresh.opaque === false && options.secret.refresh === undefined) {
    throw invalidArgument('tokenPair.options.secret.refresh is required when refresh.opaque is false');
  }
  if (options.refresh.expiresIn === undefined) {
    throw invalidArgument('tokenPair.options.refresh.expiresIn is required');
  }
  if (isNullish(options.refresh.store) || !isFunction(options.refresh.store.add)) {
    throw invalidArgument('tokenPair.options.refresh.store must implement the Store shape');
  }
}

/**
 * Produce `{ plaintext, storeKey }` for a refresh token. Custom
 * `refresh.generate` wins; otherwise mint random bytes (opaque default)
 * or a PASETO refresh token (`opaque: false`), then hash for storage.
 *
 * @param {RefreshOptions} refresh
 * @param {Record<string, unknown>} payload
 * @param {Uint8Array | import('node:crypto').KeyObject} [secret]
 * @param {number} expiresAtSec
 * @returns {Promise<{ plaintext: string, storeKey: string }>}
 */
async function _generateRefresh(refresh, payload, secret, expiresAtSec) {
  if (isFunction(refresh.generate)) {
    const result = await refresh.generate();
    if (isNullish(result) || !isString(result.plaintext) || !isString(result.storeKey)) {
      throw invalidArgument('refresh.generate: must return { plaintext, storeKey } strings');
    }
    return result;
  }

  let plaintext;
  if (refresh.opaque === false) {
    const expiresIn = expiresAtSec - Math.floor(Date.now() / 1000);
    plaintext = mintAccess({ ...payload, kind: 'refresh' }, secret, {
      purpose: refresh.purpose ?? 'local',
      expiresIn,
    });
  } else {
    const size = refresh.tokenSize ?? 32;
    if (!isInteger(size) || size < 1) {
      throw invalidArgument('refresh.tokenSize must be a positive integer');
    }
    const encoder = resolveEncoding(refresh.encoding);
    plaintext = encoder(randomBuffer(size));
  }

  const hashFn = resolveHashFn(refresh);
  const storeKey = await hashFn(plaintext);
  return { plaintext, storeKey };
}
