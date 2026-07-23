/**
 * Shared IncrStore — atomic TTL counter for replay guards and rate
 * limiting. Memory and Redis factories.
 *
 * Interface: `incr(key, ttlMs) → { count, expiresAt }`.
 * First call arms a TTL and returns `{ count: 1 }`; subsequent calls
 * before expiry increment the counter.
 *
 * Consumers: `@exortek/challenge`, `@exortek/magic-link` (rate limiter).
 */

import { isFunction, isInteger, isUndefined } from './predicates.js';
import { assertRedisClient } from './redis-guard.js';

// Memory

/**
 * @typedef {object} MemoryIncrStoreOptions
 * @property {number} [maxKeys=10000]  Hard cap; oldest entry dropped when exceeded.
 * @property {number} [sweepMs=60000]  Interval for the background TTL sweep.
 */

/**
 * @param {MemoryIncrStoreOptions} [options]
 * @param {(msg: string) => never} [wrap]  Error factory for validation.
 * @returns {{ incr: (key: string, ttlMs: number) => Promise<{ count: number, expiresAt: number }>, _size: () => number, _stop: () => void }}
 */
export function createMemoryIncrStore(options = {}, wrap) {
  const fail =
    wrap ??
    (msg => {
      throw new TypeError(msg);
    });
  const maxKeys = options.maxKeys ?? 10_000;
  const sweepMs = options.sweepMs ?? 60_000;

  if (!isInteger(maxKeys) || maxKeys < 1) {
    fail(`memoryIncrStore.maxKeys must be a positive integer; got ${maxKeys}`);
  }
  if (!isInteger(sweepMs) || sweepMs < 1000) {
    fail(`memoryIncrStore.sweepMs must be an integer >= 1000; got ${sweepMs}`);
  }

  /** @type {Map<string, { count: number, expiresAt: number }>} */
  const map = new Map();
  let timer = null;

  function peekFresh(key) {
    const entry = map.get(key);
    if (!entry) {
      return null;
    }
    if (entry.expiresAt <= Date.now()) {
      map.delete(key);
      return null;
    }
    return entry;
  }

  function sweep() {
    const t = Date.now();
    for (const [key, entry] of map) {
      if (entry.expiresAt <= t) {
        map.delete(key);
      }
    }
  }

  function scheduleSweeper() {
    if (timer) {
      return;
    }
    timer = setInterval(sweep, sweepMs);
    if (isFunction(timer.unref)) {
      timer.unref();
    }
  }

  function evictIfFull() {
    if (map.size < maxKeys) {
      return;
    }
    const oldest = map.keys().next().value;
    if (!isUndefined(oldest)) {
      map.delete(oldest);
    }
  }

  return {
    async incr(key, ttlMs) {
      scheduleSweeper();
      const existing = peekFresh(key);
      if (existing) {
        existing.count += 1;
        map.delete(key);
        map.set(key, existing);
        return { count: existing.count, expiresAt: existing.expiresAt };
      }
      evictIfFull();
      const expiresAt = Date.now() + ttlMs;
      map.set(key, { count: 1, expiresAt });
      return { count: 1, expiresAt };
    },

    _size: () => map.size,
    _stop: () => {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    },
  };
}

// Redis

const INCR_SCRIPT = `
local key = KEYS[1]
local ttl = tonumber(ARGV[1])
local count = redis.call('INCR', key)
local pttl
if count == 1 then
  redis.call('PEXPIRE', key, ttl)
  pttl = ttl
else
  pttl = redis.call('PTTL', key)
  if pttl < 0 then
    redis.call('PEXPIRE', key, ttl)
    pttl = ttl
  end
end
return { count, pttl }
`.trim();

/**
 * @typedef {object} RedisIncrStoreOptions
 * @property {string} [keyPrefix='']  Prepended to every key.
 */

/**
 * @param {object} client
 * @param {RedisIncrStoreOptions} [options]
 * @param {(msg: string) => never} [wrap]  Error factory for assertRedisClient.
 * @returns {{ incr: (key: string, ttlMs: number) => Promise<{ count: number, expiresAt: number }> }}
 */
export function createRedisIncrStore(client, options = {}, wrap) {
  assertRedisClient(
    client,
    ['eval'],
    wrap ??
      (msg => {
        throw new TypeError(msg);
      }),
  );
  const keyPrefix = options.keyPrefix ?? '';
  const k = key => `${keyPrefix}${key}`;

  return {
    async incr(key, ttlMs) {
      const raw = await client.eval(INCR_SCRIPT, 1, k(key), String(Math.max(1, Math.ceil(ttlMs))));
      const arr = Array.isArray(raw) ? raw : [raw, ttlMs];
      const count = Number(arr[0]);
      const pttl = Number(arr[1]);
      return { count, expiresAt: Date.now() + (Number.isFinite(pttl) && pttl > 0 ? pttl : ttlMs) };
    },
  };
}
