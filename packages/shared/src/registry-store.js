/**
 * Shared token-registry store — the blacklist / refresh-token registry that
 * `@exortek/jwt` and `@exortek/paseto` both ship. Memory and Redis factories.
 *
 * Interface (the `Store` shape):
 *   add(key, expiresAt, metadata?) → void
 *   has(key)                       → boolean
 *   get(key)                       → StoreRecord | null
 *   delete(key)                    → void
 *   deleteAll(filter)              → number   (metadata-match delete)
 *   markUsed(key, nowSec)          → { swapped, record } | null   (atomic CAS)
 *   size()                         → number   (memory only; Redis throws)
 *   _stop()                        → void
 *
 * The two consumers differed only in their error class and their default
 * Redis key prefix — everything else was copy-pasted, and that duplication
 * had already produced shipped Redis-dialect bugs. Both now bind this one
 * implementation.
 *
 * @typedef {Object} StoreRecord
 * @property {number} expiresAt
 * @property {Record<string, unknown>} [metadata]
 *
 * @typedef {Object} MarkUsedResult
 * @property {boolean} swapped   true if this call stamped usedAt (was null before)
 * @property {StoreRecord} record
 *
 * @typedef {Object} Store
 * @property {(key: string, expiresAt: number, metadata?: Record<string, unknown>) => Promise<void>} add
 * @property {(key: string) => Promise<boolean>} has
 * @property {(key: string) => Promise<StoreRecord | null>} get
 * @property {(key: string) => Promise<void>} delete
 * @property {(filter: Record<string, unknown>) => Promise<number>} deleteAll
 * @property {(key: string, nowSec: number) => Promise<MarkUsedResult | null>} [markUsed]
 * @property {() => number} size
 * @property {() => void} _stop
 */

import { isObject, isNonEmptyString, isFiniteNumber } from './predicates.js';
import { detectDialect, evalScript } from './redis-helpers.js';

const nowSeconds = () => Math.floor(Date.now() / 1000);

/**
 * @param {new (code: any, message: string, extra?: object) => Error} StoreError
 * @param {any} code
 * @returns {{ fail: (msg: string, cause?: unknown) => Error, isOwn: (err: unknown) => boolean }}
 */
function errorKit(StoreError, code) {
  return {
    fail: (msg, cause) => new StoreError(code, msg, cause === undefined ? undefined : { cause }),
    isOwn: err => err instanceof StoreError,
  };
}

// MEMORY

/**
 * @param {object} binding
 * @param {new (code: any, message: string, extra?: object) => Error} binding.StoreError
 * @param {any} binding.storeErrorCode
 * @param {(interval: string | number) => number} binding.parseIntervalSeconds
 *   Parse the GC interval to whole seconds (each package layers its own
 *   duration-unit conventions on top of `@exortek/shared/duration`).
 * @param {import('./registry-store.js').MemoryConfig} [options]
 * @returns {Store}
 *
 * @typedef {Object} MemoryConfig
 * @property {number} [maxSize]
 * @property {{ strategy?: 'interval' | 'lazy' | 'lru', interval?: string | number, maxSize?: number }} [gc]
 */
export function createMemoryRegistryStore({ StoreError, storeErrorCode, parseIntervalSeconds }, options) {
  const { fail } = errorKit(StoreError, storeErrorCode);

  const opts = options || {};
  const gc = opts.gc || {};
  const strategy = gc.strategy || 'interval';
  const maxSize = gc.maxSize ?? opts.maxSize ?? Infinity;
  const intervalMs =
    strategy === 'interval' || strategy === 'lru'
      ? Math.max(1000, parseIntervalSeconds(gc.interval ?? '5m') * 1000)
      : 0;

  /** @type {Map<string, StoreRecord>} */
  const map = new Map();
  /** @type {NodeJS.Timeout | null} */
  let timer = null;

  const expiredSweep = () => {
    const t = nowSeconds();
    for (const [k, v] of map) {
      if (v.expiresAt <= t) {
        map.delete(k);
      }
    }
  };

  const enforceCap = () => {
    if (map.size <= maxSize) {
      return;
    }
    // Drop insertion-order oldest until under cap. Map preserves insertion
    // order (ES2015+).
    while (map.size > maxSize) {
      const oldest = map.keys().next().value;
      if (oldest === undefined) {
        break;
      }
      map.delete(oldest);
    }
  };

  if (intervalMs > 0) {
    timer = setInterval(() => {
      expiredSweep();
      enforceCap();
    }, intervalMs);
    if (typeof timer.unref === 'function') {
      timer.unref();
    }
  }

  const matches = (record, filter) => {
    const meta = record.metadata;
    if (!meta) {
      return false;
    }
    for (const [k, v] of Object.entries(filter)) {
      if (meta[k] !== v) {
        return false;
      }
    }
    return true;
  };

  return {
    async add(key, expiresAt, metadata) {
      if (!isNonEmptyString(key)) {
        throw fail('memory-store.add: key must be a non-empty string');
      }
      if (!isFiniteNumber(expiresAt)) {
        throw fail('memory-store.add: expiresAt must be a finite NumericDate');
      }
      map.set(key, { expiresAt, ...(metadata ? { metadata } : {}) });
      if (strategy === 'lru') {
        enforceCap();
      }
    },
    async has(key) {
      const record = map.get(key);
      if (!record) {
        return false;
      }
      if (record.expiresAt <= nowSeconds()) {
        map.delete(key);
        return false;
      }
      return true;
    },
    async get(key) {
      const record = map.get(key);
      if (!record) {
        return null;
      }
      if (record.expiresAt <= nowSeconds()) {
        map.delete(key);
        return null;
      }
      return record;
    },
    async delete(key) {
      map.delete(key);
    },
    async deleteAll(filter) {
      if (!isObject(filter)) {
        throw fail('memory-store.deleteAll: filter must be an object of metadata key/value pairs');
      }
      let count = 0;
      for (const [k, record] of map) {
        if (matches(record, filter)) {
          map.delete(k);
          count++;
        }
      }
      return count;
    },
    async markUsed(key, markNowSec) {
      const record = map.get(key);
      if (!record || record.expiresAt <= nowSeconds()) {
        if (record) {
          map.delete(key);
        }
        return null;
      }
      const meta = record.metadata || {};
      if (meta.usedAt != null) {
        return { swapped: false, record };
      }
      const updated = { ...record, metadata: { ...meta, usedAt: markNowSec } };
      map.set(key, updated);
      return { swapped: true, record: updated };
    },
    size() {
      return map.size;
    },
    _stop() {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    },
  };
}

// REDIS

// Atomically stamp metadata.usedAt if it is currently null/absent.
// Returns [swapped(0|1), json] or nil when the key doesn't exist.
const MARK_USED_LUA = `
local raw = redis.call('GET', KEYS[1])
if not raw then return nil end
local data = cjson.decode(raw)
local meta = data['metadata']
if not meta then meta = {} end
if meta['usedAt'] ~= nil and meta['usedAt'] ~= cjson.null then
  return {0, raw}
end
meta['usedAt'] = tonumber(ARGV[1])
data['metadata'] = meta
local encoded = cjson.encode(data)
local ttl = redis.call('TTL', KEYS[1])
if ttl > 0 then
  redis.call('SET', KEYS[1], encoded, 'EX', ttl)
else
  redis.call('SET', KEYS[1], encoded)
end
return {1, encoded}
`;

/**
 * @param {object} binding
 * @param {new (code: any, message: string, extra?: object) => Error} binding.StoreError
 * @param {any} binding.storeErrorCode
 * @param {string} binding.defaultKeyPrefix
 * @param {object} options
 * @param {any} options.client               ioredis or redis@4 client
 * @param {string} [options.keyPrefix]
 * @param {'ioredis' | 'node-redis'} [options.dialect]
 *   Override auto-detection for wrapped/proxied clients.
 * @returns {Store}
 */
export function createRedisRegistryStore({ StoreError, storeErrorCode, defaultKeyPrefix }, options) {
  const { fail, isOwn } = errorKit(StoreError, storeErrorCode);

  if (!isObject(options) || options.client == null) {
    throw fail('redis-store: options.client is required (an ioredis or redis@4 instance)');
  }
  const client = options.client;
  const keyPrefix = options.keyPrefix || defaultKeyPrefix;
  const dialect = options.dialect ?? detectDialect(client);

  const build = key => `${keyPrefix}${key}`;

  return {
    async add(key, expiresAt, metadata) {
      if (!isNonEmptyString(key)) {
        throw fail('redis-store.add: key must be a non-empty string');
      }
      if (!isFiniteNumber(expiresAt)) {
        throw fail('redis-store.add: expiresAt must be a finite NumericDate');
      }
      const ttl = Math.max(1, Math.floor(expiresAt - nowSeconds()));
      const payload = JSON.stringify({ expiresAt, metadata: metadata || null });
      const fullKey = build(key);
      try {
        if (dialect === 'ioredis') {
          await client.set(fullKey, payload, 'EX', ttl);
        } else {
          await client.set(fullKey, payload, { EX: ttl });
        }
      } catch (err) {
        throw fail(`redis-store.add: SET failed — ${err instanceof Error ? err.message : String(err)}`, err);
      }
    },
    async has(key) {
      try {
        const n = await client.exists(build(key));
        return Number(n) > 0;
      } catch (err) {
        throw fail(`redis-store.has: EXISTS failed — ${err instanceof Error ? err.message : String(err)}`, err);
      }
    },
    async get(key) {
      try {
        const raw = await client.get(build(key));
        if (raw == null) {
          return null;
        }
        const parsed = JSON.parse(raw);
        return { expiresAt: parsed.expiresAt, ...(parsed.metadata ? { metadata: parsed.metadata } : {}) };
      } catch (err) {
        if (isOwn(err)) {
          throw err;
        }
        throw fail(`redis-store.get: failed — ${err instanceof Error ? err.message : String(err)}`, err);
      }
    },
    async delete(key) {
      try {
        await client.del(build(key));
      } catch (err) {
        throw fail(`redis-store.delete: DEL failed — ${err instanceof Error ? err.message : String(err)}`, err);
      }
    },
    async deleteAll(filter) {
      if (!isObject(filter)) {
        throw fail('redis-store.deleteAll: filter must be an object of metadata key/value pairs');
      }
      const pattern = `${keyPrefix}*`;
      // Redis cursors are protocol strings. node-redis typed them as numbers
      // through v5 but requires a string from v6 on, and the declared peer
      // range admits v6 — so seed a string for both dialects.
      let cursor = '0';
      let count = 0;
      try {
        do {
          const result =
            dialect === 'ioredis'
              ? await client.scan(cursor, 'MATCH', pattern, 'COUNT', 100)
              : await client.scan(cursor, { MATCH: pattern, COUNT: 100 });
          const [nextCursor, keys] = dialect === 'ioredis' ? result : [result.cursor, result.keys];
          cursor = nextCursor;
          for (const fullKey of keys) {
            const raw = await client.get(fullKey);
            if (raw == null) {
              continue;
            }
            let parsed;
            try {
              parsed = JSON.parse(raw);
            } catch {
              continue;
            }
            const meta = parsed && parsed.metadata;
            if (!meta) {
              continue;
            }
            let ok = true;
            for (const [k, v] of Object.entries(filter)) {
              if (meta[k] !== v) {
                ok = false;
                break;
              }
            }
            if (ok) {
              await client.del(fullKey);
              count++;
            }
          }
        } while (String(cursor) !== '0');
      } catch (err) {
        if (isOwn(err)) {
          throw err;
        }
        throw fail(`redis-store.deleteAll: SCAN/DEL failed — ${err instanceof Error ? err.message : String(err)}`, err);
      }
      return count;
    },
    async markUsed(key, markNowSec) {
      try {
        const result = await evalScript(client, MARK_USED_LUA, [build(key)], [String(markNowSec)], dialect);
        if (result == null) {
          return null;
        }
        const [swapped, json] = result;
        const parsed = JSON.parse(json);
        return {
          swapped: Number(swapped) === 1,
          record: { expiresAt: parsed.expiresAt, ...(parsed.metadata ? { metadata: parsed.metadata } : {}) },
        };
      } catch (err) {
        if (isOwn(err)) {
          throw err;
        }
        throw fail(`redis-store.markUsed: EVAL failed — ${err instanceof Error ? err.message : String(err)}`, err);
      }
    },
    size() {
      throw fail('redis-store.size: not supported — Redis has no cheap "count keys matching prefix" operation');
    },
    _stop() {
      /* nothing to clean up — TTL is native */
    },
  };
}
