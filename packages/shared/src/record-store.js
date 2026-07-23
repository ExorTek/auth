/**
 * Shared indexed record store — primary key + secondary owner-index.
 *
 * Memory and Redis factories for the CRUD + index pattern used by
 * `@exortek/apikey`, `@exortek/magic-link`, and `@exortek/session`.
 *
 * Each consuming package wraps these factories and adds its own
 * domain-specific methods (revoke, consume, etc.). The factories
 * provide the common put/get/update/list + index management.
 */

import { isString, isUndefined } from './predicates.js';
import { assertRedisClient } from './redis-guard.js';
import { createRedisHelpers } from './redis-helpers.js';

// Memory

/**
 * @typedef {object} MemoryRecordStoreConfig
 * @property {string} idField         Primary key field name ('id' | 'sid').
 * @property {string} indexField      Secondary index field name ('userId' | 'email' | 'uid').
 * @property {'shallow' | 'deep' | 'none'} [copyStrategy='shallow']
 */

/**
 * @param {MemoryRecordStoreConfig} config
 * @returns {{
 *   put: (record: object) => Promise<void>,
 *   getById: (id: string) => Promise<object|null>,
 *   update: (id: string, patch: object) => Promise<object|null>,
 *   listByIndex: (indexValue: string) => Promise<object[]>,
 *   byId: Map<string, object>,
 *   byIndex: Map<string, Set<string>>,
 *   _size: () => number,
 * }}
 */
export function createMemoryRecordStore(config) {
  const { idField, indexField, copyStrategy = 'shallow' } = config;

  /** @type {Map<string, object>} */
  const byId = new Map();
  /** @type {Map<string, Set<string>>} */
  const byIndex = new Map();

  function copy(record) {
    if (copyStrategy === 'deep') {
      return structuredClone(record);
    }
    if (copyStrategy === 'shallow') {
      return { ...record };
    }
    return record;
  }

  function addIndex(indexValue, id) {
    if (!isString(indexValue)) {
      return;
    }
    let set = byIndex.get(indexValue);
    if (!set) {
      set = new Set();
      byIndex.set(indexValue, set);
    }
    set.add(id);
  }

  function removeIndex(indexValue, id) {
    if (!isString(indexValue)) {
      return;
    }
    const set = byIndex.get(indexValue);
    if (!set) {
      return;
    }
    set.delete(id);
    if (set.size === 0) {
      byIndex.delete(indexValue);
    }
  }

  return {
    byId,
    byIndex,

    async put(record) {
      byId.set(record[idField], copy(record));
      addIndex(record[indexField], record[idField]);
    },

    async getById(id) {
      const record = byId.get(id);
      return record ? copy(record) : null;
    },

    async update(id, patch) {
      const existing = byId.get(id);
      if (!existing) {
        return null;
      }
      const oldIndex = existing[indexField];
      const next = { ...existing, ...patch };
      byId.set(id, next);
      if (!isUndefined(patch[indexField]) && patch[indexField] !== oldIndex) {
        removeIndex(oldIndex, id);
        addIndex(next[indexField], id);
      }
      return copy(next);
    },

    async listByIndex(indexValue) {
      const set = byIndex.get(indexValue);
      if (!set) {
        return [];
      }
      const out = [];
      for (const id of set) {
        const record = byId.get(id);
        if (record) {
          out.push(copy(record));
        }
      }
      return out;
    },

    _size: () => byId.size,
  };
}

// Redis

/**
 * @typedef {object} RedisRecordStoreConfig
 * @property {string} idField            Primary key field name.
 * @property {string} indexField         Secondary index field name.
 * @property {string} [keyPrefix='']
 * @property {boolean} [tombstones=false]
 * @property {string} [tombstonePrefix='rev:']
 * @property {string} [indexPrefix='u:']
 * @property {boolean} [ttl=false]       Whether records have TTL.
 * @property {(record: object, parsedTomb: object) => object} [applyTombstone]
 *   Required when `tombstones: true`. Receives the parsed record and
 *   the parsed tombstone — must mutate and return the record.
 * @property {(msg: string) => never} [wrap]
 */

/**
 * @param {object} client
 * @param {RedisRecordStoreConfig} config
 * @returns {{
 *   put: (record: object, ttlMs?: number) => Promise<void>,
 *   getById: (id: string) => Promise<object|null>,
 *   update: (id: string, patch: object, ttlMs?: number) => Promise<object|null>,
 *   listByIndex: (indexValue: string) => Promise<object[]>,
 *   readRecord: (id: string) => Promise<object|null>,
 *   writeRecord: (record: object, ttlMs?: number) => Promise<void>,
 *   writeTombstone: (id: string, data: object, ttlMs?: number) => Promise<void>,
 *   fetchIndexRecords: (indexValue: string) => Promise<[string, object|null][]>,
 *   indexAdd: (indexValue: string, id: string) => Promise<void>,
 *   indexRemove: (indexValue: string, id: string) => Promise<void>,
 *   helpers: ReturnType<typeof createRedisHelpers>,
 * }}
 */
export function createRedisRecordStore(client, config) {
  const wrap =
    config.wrap ??
    (msg => {
      throw new TypeError(msg);
    });
  assertRedisClient(client, ['get', 'set', 'del'], wrap);

  const {
    idField,
    indexField,
    keyPrefix = '',
    tombstones = false,
    tombstonePrefix = 'rev:',
    indexPrefix = 'u:',
    ttl = false,
    applyTombstone,
  } = config;

  const helpers = createRedisHelpers(client);

  const rk = id => `${keyPrefix}${id}`;
  const revk = id => `${keyPrefix}${tombstonePrefix}${id}`;
  const ik = indexValue => `${keyPrefix}${indexPrefix}${indexValue}`;

  function overlayTombstone(record, rawTomb) {
    if (!record || !rawTomb || !applyTombstone) {
      return record;
    }
    const tomb = helpers.parseRecord(rawTomb);
    if (!tomb) {
      return record;
    }
    return applyTombstone(record, tomb);
  }

  async function readRecord(id) {
    if (tombstones) {
      const [rawRecord, rawTomb] = await helpers.mget([rk(id), revk(id)]);
      const record = helpers.parseRecord(rawRecord);
      return record ? overlayTombstone(record, rawTomb) : null;
    }
    return helpers.parseRecord(await client.get(rk(id)));
  }

  async function writeRecord(record, ttlMs) {
    const value = JSON.stringify(record);
    if (ttl && ttlMs !== undefined) {
      await helpers.setWithTTL(rk(record[idField]), value, ttlMs);
    } else {
      await helpers.setPlain(rk(record[idField]), value);
    }
  }

  async function writeTombstone(id, data, ttlMs) {
    const value = JSON.stringify(data);
    if (ttl && ttlMs !== undefined) {
      await helpers.setWithTTL(revk(id), value, ttlMs);
    } else {
      await helpers.setPlain(revk(id), value);
    }
  }

  async function indexAdd(indexValue, id) {
    await helpers.sadd(ik(indexValue), id);
  }

  async function indexRemove(indexValue, id) {
    await helpers.srem(ik(indexValue), id);
  }

  async function fetchIndexRecords(indexValue) {
    const ids = await helpers.smembers(ik(indexValue));
    if (!ids || ids.length === 0) {
      return [];
    }
    const keys = [];
    for (const id of ids) {
      keys.push(rk(id));
      if (tombstones) {
        keys.push(revk(id));
      }
    }
    const rows = await helpers.mget(keys);
    const stride = tombstones ? 2 : 1;
    const pairs = [];
    for (let i = 0; i < ids.length; i++) {
      const raw = rows[i * stride];
      const rawTomb = tombstones ? rows[i * stride + 1] : null;
      const record = helpers.parseRecord(raw);
      if (!record) {
        await indexRemove(indexValue, ids[i]);
        pairs.push([ids[i], null]);
        continue;
      }
      pairs.push([ids[i], overlayTombstone(record, rawTomb)]);
    }
    return pairs;
  }

  return {
    async put(record, ttlMs) {
      await writeRecord(record, ttlMs);
      if (isString(record[indexField])) {
        await indexAdd(record[indexField], record[idField]);
      }
    },

    async getById(id) {
      return readRecord(id);
    },

    async update(id, patch, ttlMs) {
      const existing = await readRecord(id);
      if (!existing) {
        return null;
      }
      const oldIndex = existing[indexField];
      const next = { ...existing, ...patch };
      await writeRecord(next, ttlMs);
      if (!isUndefined(patch[indexField]) && patch[indexField] !== oldIndex) {
        if (isString(oldIndex)) {
          await indexRemove(oldIndex, id);
        }
        if (isString(next[indexField])) {
          await indexAdd(next[indexField], id);
        }
      }
      return next;
    },

    async listByIndex(indexValue) {
      const pairs = await fetchIndexRecords(indexValue);
      return pairs.filter(([, r]) => r !== null).map(([, r]) => r);
    },

    readRecord,
    writeRecord,
    writeTombstone,
    fetchIndexRecords,
    indexAdd,
    indexRemove,
    helpers,
  };
}
