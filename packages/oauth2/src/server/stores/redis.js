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
import { createRedisIncrStore } from '@exortek/shared/incr-store';
import { isFunction } from '@exortek/shared/predicates';

const DEFAULT_PREFIX = 'oauth2:';
// Claim-key lifetime for a family that carries no expiry (legacy records).
const CLAIM_FALLBACK_TTL_MS = 30 * 24 * 60 * 60 * 1000;

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
  const claimKey = token => `${options.keyPrefix ?? DEFAULT_PREFIX}refresh:claim:${token}`;

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
    // Compare-and-set across nodes: the first redemption creates the claim
    // key (SET NX) and wins; a concurrent one finds it and resolves false,
    // which the grant treats as reuse. The claim lives as long as the
    // family, so a late replay is still caught after the record is gone.
    async rotate(oldToken, next) {
      const won = await store.helpers.setIfAbsent(claimKey(oldToken), '1', ttlOf(next) ?? CLAIM_FALLBACK_TTL_MS);
      if (!won) {
        return false;
      }
      await store.update(oldToken, { used: true });
      await store.put(next, ttlOf(next));
      return true;
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

  const self = {
    async save(record, ttlMs) {
      const expiresAt = Date.now() + ttlMs;
      await helpers.setWithTTL(dk(record.deviceCode), JSON.stringify({ ...record, expiresAt }), ttlMs);
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
    // KEEPTTL: an update (every poll writes lastPolledAt) never extends the
    // code's life.
    async update(deviceCode, patch) {
      const existing = await self.getByDeviceCode(deviceCode);
      if (!existing) {
        return;
      }
      await helpers.setKeepTTL(dk(deviceCode), JSON.stringify({ ...existing, ...patch }));
      if (patch.status === 'redeemed' || patch.status === 'denied') {
        await client.del(uk(existing.userCode));
      }
    },
    // Single redemption across nodes: the first poll to create the redeem
    // claim (SET NX) wins; any concurrent poll resolves false.
    async redeem(deviceCode) {
      const existing = await self.getByDeviceCode(deviceCode);
      if (!existing || existing.status !== 'approved') {
        return false;
      }
      const ttlMs = Math.max(1, (existing.expiresAt ?? Date.now() + 1000) - Date.now());
      if (!(await helpers.setIfAbsent(`${dk(deviceCode)}:redeemed`, '1', ttlMs))) {
        return false;
      }
      await self.update(deviceCode, { status: 'redeemed' });
      return true;
    },
  };
  return self;
}

/**
 * Shared jti replay store (`stores.replay`) — DPoP proofs, client assertions
 * and request objects replayed against a different node are caught. Each id
 * is an INCR with a TTL; the first sighting counts 1.
 *
 * @param {any} client
 * @param {{ keyPrefix?: string }} [options]
 * @returns {import('../security/replay.js').ReplayStore}
 */
export function createRedisReplayStore(client, options = {}) {
  return createRedisIncrStore(client, { keyPrefix: `${options.keyPrefix ?? DEFAULT_PREFIX}replay:` });
}
