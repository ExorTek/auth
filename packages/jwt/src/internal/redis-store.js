/**
 * Redis-backed blacklist / refresh-token store.
 *
 * Compatible with both `ioredis` (`client.set(key, value, 'EX', ttl)`)
 * and `redis@4` (`client.set(key, value, { EX: ttl })`). We adapt at
 * runtime by inspecting the client — no version-specific import.
 *
 * TTL is handled natively by Redis (`EX` in seconds) — the interval GC
 * a memory store needs does not apply here.
 *
 * `deleteAll(filter)` uses `SCAN` + metadata JSON match. Redis has no
 * built-in secondary index, so this scales linearly with the number of
 * blacklist entries. For very large deployments, callers should track
 * family membership out of band and delete keys explicitly.
 */

import { JwtError, ErrorCode } from './errors.js';

/**
 * @typedef {import('./memory-store.js').Store} Store
 * @typedef {import('./memory-store.js').StoreRecord} StoreRecord
 *
 * @typedef {Object} RedisConfig
 * @property {any} client        ioredis or redis@4 client
 * @property {string} [keyPrefix]
 */

/**
 * @param {RedisConfig} options
 * @returns {Store}
 */
export function createRedisStore(options) {
  if (options == null || typeof options !== 'object' || options.client == null) {
    throw new JwtError(
      ErrorCode.STORE_ERROR,
      'redis-store: options.client is required (an ioredis or redis@4 instance)',
    );
  }
  const client = options.client;
  const keyPrefix = options.keyPrefix || 'jwt:bl:';
  const dialect = _detectDialect(client);

  const build = key => `${keyPrefix}${key}`;

  const now = () => Math.floor(Date.now() / 1000);

  return {
    async add(key, expiresAt, metadata) {
      if (typeof key !== 'string' || key.length === 0) {
        throw new JwtError(ErrorCode.STORE_ERROR, 'redis-store.add: key must be a non-empty string');
      }
      if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt)) {
        throw new JwtError(ErrorCode.STORE_ERROR, 'redis-store.add: expiresAt must be a finite NumericDate');
      }
      const ttl = Math.max(1, Math.floor(expiresAt - now()));
      const payload = JSON.stringify({ expiresAt, metadata: metadata || null });
      const fullKey = build(key);
      try {
        if (dialect === 'ioredis') {
          await client.set(fullKey, payload, 'EX', ttl);
        } else {
          await client.set(fullKey, payload, { EX: ttl });
        }
      } catch (err) {
        throw new JwtError(
          ErrorCode.STORE_ERROR,
          `redis-store.add: SET failed — ${err instanceof Error ? err.message : String(err)}`,
          { cause: err },
        );
      }
    },
    async has(key) {
      try {
        const n = await client.exists(build(key));
        return Number(n) > 0;
      } catch (err) {
        throw new JwtError(
          ErrorCode.STORE_ERROR,
          `redis-store.has: EXISTS failed — ${err instanceof Error ? err.message : String(err)}`,
          { cause: err },
        );
      }
    },
    async get(key) {
      try {
        const raw = await client.get(build(key));
        if (raw == null) {
          return null;
        }
        const parsed = JSON.parse(raw);
        return {
          expiresAt: parsed.expiresAt,
          ...(parsed.metadata ? { metadata: parsed.metadata } : {}),
        };
      } catch (err) {
        if (err instanceof JwtError) {
          throw err;
        }
        throw new JwtError(
          ErrorCode.STORE_ERROR,
          `redis-store.get: failed — ${err instanceof Error ? err.message : String(err)}`,
          { cause: err },
        );
      }
    },
    async delete(key) {
      try {
        await client.del(build(key));
      } catch (err) {
        throw new JwtError(
          ErrorCode.STORE_ERROR,
          `redis-store.delete: DEL failed — ${err instanceof Error ? err.message : String(err)}`,
          { cause: err },
        );
      }
    },
    async deleteAll(filter) {
      if (filter == null || typeof filter !== 'object') {
        throw new JwtError(
          ErrorCode.STORE_ERROR,
          'redis-store.deleteAll: filter must be an object of metadata key/value pairs',
        );
      }
      const pattern = `${keyPrefix}*`;
      let cursor = dialect === 'ioredis' ? '0' : 0;
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
        } while (dialect === 'ioredis' ? cursor !== '0' : Number(cursor) !== 0);
      } catch (err) {
        if (err instanceof JwtError) {
          throw err;
        }
        throw new JwtError(
          ErrorCode.STORE_ERROR,
          `redis-store.deleteAll: SCAN/DEL failed — ${err instanceof Error ? err.message : String(err)}`,
          { cause: err },
        );
      }
      return count;
    },
    size() {
      throw new JwtError(
        ErrorCode.STORE_ERROR,
        'redis-store.size: not supported — Redis has no cheap "count keys matching prefix" operation',
      );
    },
    _stop() {
      /* nothing to clean up — TTL is native */
    },
  };
}

/**
 * Detect whether the client is `ioredis`-style or `redis@4`-style.
 * `ioredis`'s `set` takes positional args (`'EX', ttl`); `redis@4`'s
 * takes an options object. We probe the constructor name; users with
 * a wrapped client can force via `options.dialect` if we add that
 * later.
 *
 * @param {any} client
 * @returns {'ioredis' | 'node-redis'}
 */
function _detectDialect(client) {
  const name = (client && client.constructor && client.constructor.name) || '';
  if (name === 'Redis' || name === 'Cluster') {
    // ioredis — top-level classes are `Redis` and `Cluster`.
    return 'ioredis';
  }
  return 'node-redis';
}
