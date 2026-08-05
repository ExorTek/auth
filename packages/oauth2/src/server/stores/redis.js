/**
 * Redis-backed authorization-server stores — the production backing for
 * the four store contracts `createServer` consumes, cluster-safe behind
 * the identical shape as the in-memory defaults. Inject them per store:
 *
 *   createServer({
 *     stores: {
 *       authCode: createRedisAuthCodeStore(client),
 *       refresh:  createRedisRefreshStore(client),
 *       par:      createRedisParStore(client),
 *       device:   createRedisDeviceStore(client),
 *     },
 *   });
 *
 * State lives in Redis, so a code issued on one node redeems on any other
 * and the in-memory single-process caveat is gone. Works with any client
 * exposing `get / set / del / mget / sadd / srem / smembers` — `ioredis`,
 * `node-redis@4+`, and `@upstash/redis` are the verified targets.
 *
 * The short-lived single-use records (auth code / PAR / device) ride
 * Redis key TTLs, so eviction is the server's job, not ours. The refresh
 * family reuses the token-family record-store idiom (rotation + a
 * revocation tombstone that a concurrent rotation can never lose).
 */
import { createRedisHelpers } from '@exortek/shared/redis-helpers';
import { createRedisRecordStore } from '@exortek/shared/record-store';
import { isFunction } from '@exortek/shared/predicates';

const DEFAULT_PREFIX = 'oauth2:';

/**
 * GET-then-DEL a key, atomically when the client supports `GETDEL`
 * (node-redis `getDel`, ioredis/Upstash `getdel`), else best-effort
 * GET + DEL. Single-use redemption of a code / request_uri.
 *
 * @param {any} client
 * @param {string} key
 * @returns {Promise<string | null>}
 */
async function getDel(client, key) {
  if (isFunction(client.getdel)) {
    return client.getdel(key);
  }
  if (isFunction(client.getDel)) {
    return client.getDel(key);
  }
  const raw = await client.get(key);
  if (raw != null) {
    await client.del(key);
  }
  return raw;
}

/**
 * A short-TTL single-use record store (auth code / PAR share this shape):
 * `save` writes with a Redis TTL, `consume` redeems exactly once.
 *
 * @param {any} client
 * @param {string} prefix
 * @returns {{ save: Function, consume: Function }}
 */
function singleUseStore(client, prefix) {
  const helpers = createRedisHelpers(client);
  return {
    async save(key, record, ttlMs) {
      await helpers.setWithTTL(prefix + key, JSON.stringify(record), ttlMs);
    },
    async consume(key) {
      const raw = await getDel(client, prefix + key);
      return helpers.parseRecord(raw) ?? undefined;
    },
  };
}

/**
 * @param {any} client
 * @param {{ keyPrefix?: string }} [options]
 * @returns {import('../stores.js').AuthCodeStore}
 */
export function createRedisAuthCodeStore(client, options = {}) {
  return singleUseStore(client, `${options.keyPrefix ?? DEFAULT_PREFIX}code:`);
}

/**
 * @param {any} client
 * @param {{ keyPrefix?: string }} [options]
 * @returns {import('../stores.js').ParStore}
 */
export function createRedisParStore(client, options = {}) {
  return singleUseStore(client, `${options.keyPrefix ?? DEFAULT_PREFIX}par:`);
}

/**
 * Refresh family with rotation + reuse detection over the shared
 * record-store idiom. A revocation is a tombstone (never a plain update)
 * so a concurrent rotation on another node cannot silently un-revoke the
 * family. Records carry `expiresAt`, mirrored to a Redis TTL.
 *
 * @param {any} client
 * @param {{ keyPrefix?: string }} [options]
 * @returns {import('../stores.js').RefreshStore}
 */
export function createRedisRefreshStore(client, options = {}) {
  const store = createRedisRecordStore(client, {
    idField: 'token',
    indexField: 'familyId',
    keyPrefix: `${options.keyPrefix ?? DEFAULT_PREFIX}refresh:`,
    ttl: true,
    tombstones: true,
    applyTombstone(record, tomb) {
      record.used = record.used || tomb.used === true;
      record.revoked = record.revoked || tomb.revoked === true;
      return record;
    },
  });

  /** @param {{ expiresAt?: number }} record */
  const ttlOf = record =>
    typeof record.expiresAt === 'number' ? Math.max(1, record.expiresAt - Date.now()) : undefined;

  return {
    async save(record) {
      await store.put(record, ttlOf(record));
    },
    async get(token) {
      const record = /** @type {any} */ (await store.getById(token));
      if (record && typeof record.expiresAt === 'number' && record.expiresAt <= Date.now()) {
        return null;
      }
      return record;
    },
    async rotate(oldToken, next) {
      await store.update(oldToken, { used: true });
      await store.put(next, ttlOf(next));
    },
    async revokeFamily(familyId) {
      const members = await store.listByIndex(familyId);
      for (const member of members) {
        // A tombstone can never be lost to an in-flight rotation.
        await store.writeTombstone(member.token, { used: true, revoked: true }, ttlOf(member));
      }
    },
  };
}

/**
 * Device flow (RFC 8628): the `device_code` record plus a `user_code` →
 * `device_code` reverse pointer, each on its own Redis TTL.
 *
 * @param {any} client
 * @param {{ keyPrefix?: string }} [options]
 * @returns {import('../stores.js').DeviceStore}
 */
export function createRedisDeviceStore(client, options = {}) {
  const prefix = `${options.keyPrefix ?? DEFAULT_PREFIX}device:`;
  const dk = deviceCode => `${prefix}d:${deviceCode}`;
  const uk = userCode => `${prefix}u:${userCode}`;
  const helpers = createRedisHelpers(client);
  // Re-arm window for an update that carries no explicit TTL (mirrors the
  // in-memory store): a device flow is minutes-long.
  const REEARM_MS = 600_000;

  const self = {
    async save(record, ttlMs) {
      await helpers.setWithTTL(dk(record.deviceCode), JSON.stringify(record), ttlMs);
      await helpers.setWithTTL(uk(record.userCode), record.deviceCode, ttlMs);
    },
    async getByDeviceCode(deviceCode) {
      return helpers.parseRecord(await client.get(dk(deviceCode))) ?? undefined;
    },
    async getByUserCode(userCode) {
      const deviceCode = await client.get(uk(userCode));
      if (deviceCode == null) {
        return undefined;
      }
      return self.getByDeviceCode(deviceCode);
    },
    async update(deviceCode, patch) {
      const existing = await self.getByDeviceCode(deviceCode);
      if (!existing) {
        return;
      }
      await helpers.setWithTTL(dk(deviceCode), JSON.stringify({ ...existing, ...patch }), REEARM_MS);
      if (patch.status === 'redeemed' || patch.status === 'denied') {
        await client.del(uk(existing.userCode));
      }
    },
  };
  return self;
}
