/**
 * In-memory default stores for the authorization server. Each is a thin
 * domain wrapper over a small TTL map (short-lived single-use records) or
 * `@exortek/shared/record-store` (the refresh family with reuse
 * detection) — the same store idioms the token-family packages already
 * use, no new shape invented. Every store is swappable: `createServer`
 * accepts `{ stores: { authCode, refresh, par, device } }` so a
 * deployment can back them with Redis behind the identical contract.
 *
 * The four contracts:
 *   - auth-code — short-TTL, single-use `consume` (RFC 6749 §4.1.2, one
 *     redemption only; a replayed code is rejected AND, per §4.1.2, the
 *     caller SHOULD revoke tokens already issued for it).
 *   - refresh — rotating family with reuse detection (RFC 9700 §4.14): a
 *     presented-but-already-rotated token revokes the whole family.
 *   - PAR — short-TTL, single-use `request_uri` → pushed parameters
 *     (RFC 9126).
 *   - device — `device_code` / `user_code` pending authorization
 *     (RFC 8628), approved or denied out of band.
 */
import { createMemoryRecordStore } from '@exortek/shared/record-store';
import { isFunction, isNumber, isObject } from '@exortek/shared/predicates';

// TTL PRIMITIVE

/**
 * A minimal expiring key→value map. `get` treats an expired entry as
 * absent (and evicts it); `consume` additionally deletes on a hit so a
 * record can be redeemed at most once.
 *
 * A background sweep evicts expired entries so an unredeemed record (a
 * code/PAR/device request that is never presented) cannot accumulate — a
 * lazy-only map would leak those forever. The sweep timer is `unref()`ed
 * so it never keeps the process alive.
 *
 * These in-memory maps are single-process by design: they are the
 * batteries-included default, not the production backing store. A
 * multi-node deployment injects Redis-backed stores behind the identical
 * contract (`createServer({ stores })`).
 *
 * @template V
 * @param {{ sweepIntervalMs?: number }} [options]
 * @returns {{ set: (k: string, v: V, ttlMs: number) => void, get: (k: string) => V | undefined, consume: (k: string) => V | undefined, delete: (k: string) => void }}
 */
function createTtlMap({ sweepIntervalMs = 60_000 } = {}) {
  /** @type {Map<string, { value: unknown, expiresAt: number }>} */
  const map = new Map();

  function read(key) {
    const entry = map.get(key);
    if (!entry) {
      return undefined;
    }
    if (entry.expiresAt <= Date.now()) {
      map.delete(key);
      return undefined;
    }
    return entry;
  }

  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of map) {
      if (entry.expiresAt <= now) {
        map.delete(key);
      }
    }
  }, sweepIntervalMs);
  // Do not let the sweep timer hold the event loop open.
  if (typeof sweep.unref === 'function') {
    sweep.unref();
  }

  return {
    set(key, value, ttlMs) {
      map.set(key, { value, expiresAt: Date.now() + ttlMs });
    },
    get(key) {
      return read(key)?.value;
    },
    consume(key) {
      const entry = read(key);
      if (!entry) {
        return undefined;
      }
      map.delete(key);
      return entry.value;
    },
    delete(key) {
      map.delete(key);
    },
  };
}

// AUTH-CODE STORE

/**
 * @typedef {Object} AuthCodeRecord
 * @property {string} clientId
 * @property {string} redirectUri
 * @property {string} codeChallenge
 * @property {string[]} scope
 * @property {string} [nonce]
 * @property {string} [subject]
 * @property {number} [authTime]             unix seconds of the authentication event → OIDC `auth_time`
 * @property {string} [resource]
 * @property {unknown} [authorizationDetails]
 * @property {string} [dpopJkt]              DPoP `jkt` bound at the authorize step (RFC 9449 §10)
 *
 * @typedef {Object} AuthCodeStore
 * @property {(code: string, record: AuthCodeRecord, ttlMs: number) => void | Promise<void>} save
 * @property {(code: string) => (AuthCodeRecord | undefined) | Promise<AuthCodeRecord | undefined>} consume
 */

/** @returns {AuthCodeStore} */
export function createAuthCodeStore() {
  const map = createTtlMap();
  return {
    save(code, record, ttlMs) {
      map.set(code, record, ttlMs);
    },
    consume(code) {
      return /** @type {AuthCodeRecord | undefined} */ (map.consume(code));
    },
  };
}

// REFRESH STORE (rotating family + reuse detection)

/**
 * @typedef {Object} RefreshRecord
 * @property {string} token          the opaque refresh token (primary key)
 * @property {string} familyId       shared across every rotation of one grant
 * @property {string} clientId
 * @property {string[]} scope
 * @property {string} [subject]
 * @property {string} [resource]
 * @property {string} [dpopJkt]
 * @property {number} [expiresAt]    epoch ms after which the token is expired
 * @property {boolean} [used]        set when rotated away — a later presentation is reuse
 * @property {boolean} [revoked]     set when the whole family was burned (reuse detected)
 *
 * @typedef {Object} RefreshStore
 * @property {(record: RefreshRecord) => Promise<void>} save
 * @property {(token: string) => Promise<RefreshRecord | null>} get
 * @property {(oldToken: string, next: RefreshRecord) => Promise<boolean | void>} rotate
 *   Atomically claim `oldToken` and persist `next`. Resolve `false` when the
 *   token was already rotated or revoked (a concurrent redemption won), so the
 *   grant treats it as reuse. A store that resolves nothing is treated as a
 *   successful rotation (pre-CAS custom stores).
 * @property {(familyId: string) => Promise<void>} revokeFamily
 */

/**
 * @param {{ sweepIntervalMs?: number }} [options]
 * @returns {RefreshStore}
 */
export function createRefreshStore({ sweepIntervalMs = 60_000 } = {}) {
  const store = createMemoryRecordStore({ idField: 'token', indexField: 'familyId' });

  // The record store has no TTL of its own: evict expired tokens in the
  // background so a family that is never presented again cannot leak.
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [token, record] of store.byId) {
      const { expiresAt, familyId } = /** @type {RefreshRecord} */ (record);
      if (isNumber(expiresAt) && expiresAt <= now) {
        store.byId.delete(token);
        const members = store.byIndex.get(familyId);
        members?.delete(token);
        if (members?.size === 0) {
          store.byIndex.delete(familyId);
        }
      }
    }
  }, sweepIntervalMs);
  if (isFunction(sweep.unref)) {
    sweep.unref();
  }

  return {
    async save(record) {
      await store.put(record);
    },
    async get(token) {
      const record = /** @type {RefreshRecord | null} */ (await store.getById(token));
      // An expired refresh token is treated as absent.
      if (record && isNumber(record.expiresAt) && record.expiresAt <= Date.now()) {
        return null;
      }
      return record;
    },
    // Compare-and-set: the check and the `used` flip happen in one
    // synchronous step, so of two concurrent redemptions exactly one wins.
    async rotate(oldToken, next) {
      const existing = /** @type {RefreshRecord | undefined} */ (store.byId.get(oldToken));
      if (!existing || existing.used === true || existing.revoked === true) {
        return false;
      }
      existing.used = true;
      await store.put(next);
      return true;
    },
    async revokeFamily(familyId) {
      const members = await store.listByIndex(familyId);
      for (const member of members) {
        await store.update(member.token, { used: true, revoked: true });
      }
    },
  };
}

// PAR STORE (RFC 9126)

/**
 * @typedef {Object} ParStore
 * @property {(requestUri: string, params: Record<string, unknown>, ttlMs: number) => void | Promise<void>} save
 * @property {(requestUri: string) => (Record<string, unknown> | undefined) | Promise<Record<string, unknown> | undefined>} consume
 */

/** @returns {ParStore} */
export function createParStore() {
  const map = createTtlMap();
  return {
    save(requestUri, params, ttlMs) {
      map.set(requestUri, params, ttlMs);
    },
    consume(requestUri) {
      return /** @type {Record<string, unknown> | undefined} */ (map.consume(requestUri));
    },
  };
}

// DEVICE STORE (RFC 8628)

/**
 * @typedef {Object} DeviceRecord
 * @property {string} deviceCode
 * @property {string} userCode
 * @property {string} clientId
 * @property {string[]} scope
 * @property {'pending' | 'approved' | 'denied' | 'redeemed'} status
 * @property {string} [subject]           set on approval
 * @property {number} [lastPolledAt]      for slow_down enforcement
 * @property {number} [expiresAt]         epoch ms; set by the store on save and never extended
 *
 * @typedef {Object} DeviceStore
 * @property {(record: DeviceRecord, ttlMs: number) => void | Promise<void>} save
 * @property {(deviceCode: string) => (DeviceRecord | undefined) | Promise<DeviceRecord | undefined>} getByDeviceCode
 * @property {(userCode: string) => (DeviceRecord | undefined) | Promise<DeviceRecord | undefined>} getByUserCode
 * @property {(deviceCode: string, patch: Partial<DeviceRecord>) => void | Promise<void>} update
 *   Patch a record without extending its lifetime.
 * @property {(deviceCode: string) => boolean | Promise<boolean>} [redeem]
 *   Atomically flip an `approved` record to `redeemed`; resolve whether this
 *   call did it. Optional for custom stores (the grant then falls back to a
 *   non-atomic `update`), implemented by the built-in stores.
 */

/** @returns {DeviceStore} */
export function createDeviceStore() {
  const byDeviceCode = createTtlMap();
  // user_code → device_code, on the same TTL as the record it points at.
  const userToDevice = createTtlMap();

  return {
    save(record, ttlMs) {
      const expiresAt = Date.now() + ttlMs;
      byDeviceCode.set(record.deviceCode, { ...record, expiresAt }, ttlMs);
      userToDevice.set(record.userCode, record.deviceCode, ttlMs);
    },
    getByDeviceCode(deviceCode) {
      return /** @type {DeviceRecord | undefined} */ (byDeviceCode.get(deviceCode));
    },
    getByUserCode(userCode) {
      const deviceCode = /** @type {string | undefined} */ (userToDevice.get(userCode));
      return deviceCode ? this.getByDeviceCode(deviceCode) : undefined;
    },
    update(deviceCode, patch) {
      const existing = /** @type {DeviceRecord | undefined} */ (byDeviceCode.get(deviceCode));
      if (!existing) {
        return;
      }
      // Keep the original expiry: polling must never extend a device code.
      const remaining = /** @type {number} */ (existing.expiresAt) - Date.now();
      byDeviceCode.set(deviceCode, { ...existing, ...patch }, remaining);
      // Once the code is spent (redeemed/denied), the one-time `user_code`
      // is done — free the reverse index eagerly rather than waiting for
      // TTL, so a verified device flow leaves nothing behind.
      if (patch.status === 'redeemed' || patch.status === 'denied') {
        userToDevice.delete(existing.userCode);
      }
    },
    // Check-and-flip in one synchronous step: exactly one poll redeems.
    redeem(deviceCode) {
      const existing = /** @type {DeviceRecord | undefined} */ (byDeviceCode.get(deviceCode));
      if (!existing || existing.status !== 'approved') {
        return false;
      }
      this.update(deviceCode, { status: 'redeemed' });
      return true;
    },
  };
}

/**
 * @param {unknown} store
 * @param {string[]} methods
 * @returns {boolean}
 */
export function isStoreShaped(store, methods) {
  return isObject(store) && methods.every(m => isFunction(/** @type {Record<string, unknown>} */ (store)[m]));
}
