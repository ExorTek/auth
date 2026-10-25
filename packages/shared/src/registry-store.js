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
import { createRedisHelpers, detectDialect, evalScript } from './redis-helpers.js';

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

// Atomically stamp `usedAt` if the record has not been used yet.
// Returns [swapped(0|1), raw] or nil when the key doesn't exist.
//
// The stamp is spliced onto the front of the stored JSON as a top-level
// `usedAt` field instead of decoding and re-encoding the record with cjson:
// cjson turns empty arrays into `{}`, prints numbers with 14 significant
// digits, and decodes `metadata: null` to a userdata value the script
// cannot index — every rotation would have silently rewritten the token
// payload kept in the metadata. `add` always writes `{"expiresAt":…`, so a
// record that starts with `{"usedAt":` has been stamped. KEEPTTL keeps the
// record's expiry.
const MARK_USED_LUA = `
local raw = redis.call('GET', KEYS[1])
if not raw then return nil end
if string.sub(raw, 1, 10) == '{"usedAt":' then
  return {0, raw}
end
local stamped = '{"usedAt":' .. ARGV[1] .. ',' .. string.sub(raw, 2)
redis.call('SET', KEYS[1], stamped, 'KEEPTTL')
return {1, stamped}
`;

/**
 * Decode a stored Redis record. A `usedAt` stamped by {@link MARK_USED_LUA}
 * sits at the top level and is folded into `metadata`, the shape the memory
 * store returns. A `metadata.usedAt` written by an earlier version (which
 * stamped inside the metadata) wins, so a token used before an upgrade stays
 * used.
 *
 * @param {any} parsed  the JSON-parsed stored value
 * @returns {StoreRecord}
 */
function decodeRecord(parsed) {
  /** @type {Record<string, unknown> | null} */
  let metadata = isObject(parsed.metadata) ? parsed.metadata : null;
  if (parsed.usedAt != null && (metadata === null || metadata.usedAt == null)) {
    metadata = { ...metadata, usedAt: parsed.usedAt };
  }
  return { expiresAt: parsed.expiresAt, ...(metadata ? { metadata } : {}) };
}

/**
 * Does a raw stored value's metadata match every `filter` entry? Values that
 * are gone or not records never match.
 *
 * @param {string | null} raw
 * @param {Record<string, unknown>} filter
 * @returns {boolean}
 */
function matchesFilter(raw, filter) {
  if (raw == null) {
    return false;
  }
  let meta;
  try {
    meta = decodeRecord(JSON.parse(raw)).metadata;
  } catch {
    return false;
  }
  if (!meta) {
    return false;
  }
  for (const [k, v] of Object.entries(filter)) {
    if (meta[k] !== v) {
      return false;
    }
  }
  return true;
}

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
  const helpers = createRedisHelpers(client);

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
        return decodeRecord(JSON.parse(raw));
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
      // Glob-escape the prefix: a `*`, `?` or `[` in it would otherwise
      // widen the match to keys outside this store.
      const pattern = `${keyPrefix.replace(/[*?[\]\\]/g, '\\$&')}*`;
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
          // One MGET and one DEL per SCAN page instead of a round trip per key.
          const values = await helpers.mget(keys);
          const doomed = keys.filter((_fullKey, i) => matchesFilter(values[i], filter));
          if (doomed.length > 0) {
            count += Number(await client.del(doomed));
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
        const [swapped, raw] = result;
        const parsed = JSON.parse(raw);
        // A record stamped by an earlier version carries its own
        // `metadata.usedAt` — already used, so this call did not swap.
        const legacyUsed = isObject(parsed.metadata) && parsed.metadata.usedAt != null;
        return { swapped: Number(swapped) === 1 && !legacyUsed, record: decodeRecord(parsed) };
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
