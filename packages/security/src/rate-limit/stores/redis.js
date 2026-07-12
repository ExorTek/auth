import { SecurityError, ErrorCode } from '../../internal/errors.js';

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

const READ_SCRIPT = `
local key = KEYS[1]
local current = redis.call('GET', key)
if not current then
  return { 0, -1 }
end
local ttl = redis.call('PTTL', key)
if ttl < 0 then
  ttl = 0
end
return { tonumber(current), ttl }
`.trim();

/**
 * Redis-compatible store. Works with any client that exposes:
 *   - `eval(script, numkeys, ...args)`  → number | string
 *   - `pttl(key)`                       → number (ms; -2 missing, -1 no ttl)
 *   - `get(key)`                        → string | null
 *   - `set(key, value, 'PX', ms)`       → 'OK'
 *   - `del(key)`                        → number
 *
 * Verified compat: `ioredis`, `node-redis` (v4+), `@upstash/redis` (HTTP,
 * works on Cloudflare Workers / Vercel Edge / Deno Deploy).
 *
 * Atomicity:
 *   - `incr` runs a single Lua script that INCR's the key and PEXPIRE's it
 *     only when the key is fresh (count == 1). TTL anchors to the first
 *     increment in the window — correct for fixed / token-bucket.
 *   - `read` runs a Lua script (GET + PTTL) so the snapshot is consistent
 *     even under contention.
 *
 * Optimization: when the client is `ioredis` (detected via `defineCommand`),
 * both scripts are registered once as named commands. Subsequent calls go
 * out as `EVALSHA`, saving the script body on every request.
 *
 * Namespacing: every key is prefixed with `rl:` by default so this adapter
 * doesn't collide with your application keys. Configurable via `prefix`.
 *
 * @param {object} client                 Redis-compatible client instance.
 * @param {{ prefix?: string }} [options]
 * @returns {import('../index.js').RateLimitStore}
 */
export function redisStore(client, options = {}) {
  if (!client || typeof client !== 'object') {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      'redisStore(client) requires a Redis-compatible client (ioredis, node-redis, or @upstash/redis)',
    );
  }
  for (const name of ['eval', 'get', 'set', 'del']) {
    if (typeof client[name] !== 'function') {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        `redisStore: client.${name} is required — is this a Redis-compatible client?`,
      );
    }
  }

  const prefix = options.prefix ?? 'rl:';
  const k = key => `${prefix}${key}`;

  // ioredis exposes `defineCommand` — cache the scripts once so subsequent
  // calls go out as EVALSHA (saves bandwidth + parse cost per request).
  // We namespace the command names to avoid collision if the same client is
  // shared with another library that also calls defineCommand.
  const useDefined = typeof client.defineCommand === 'function';
  if (useDefined) {
    if (typeof client.exortekRlIncr !== 'function') {
      client.defineCommand('exortekRlIncr', { numberOfKeys: 1, lua: INCR_SCRIPT });
    }
    if (typeof client.exortekRlRead !== 'function') {
      client.defineCommand('exortekRlRead', { numberOfKeys: 1, lua: READ_SCRIPT });
    }
  }

  async function runIncr(fullKey, ttlMs) {
    if (useDefined) {
      return client.exortekRlIncr(fullKey, ttlMs);
    }
    // node-redis v4 / Upstash: options-object EVAL. ioredis without
    // defineCommand support (shouldn't happen, but fall through cleanly)
    // uses positional args.
    if (client.eval.length >= 2 && !client.sendCommand) {
      return client.eval(INCR_SCRIPT, 1, fullKey, ttlMs);
    }
    return client.eval(INCR_SCRIPT, { keys: [fullKey], arguments: [String(ttlMs)] });
  }

  async function runRead(fullKey) {
    if (useDefined) {
      return client.exortekRlRead(fullKey);
    }
    if (client.eval.length >= 2 && !client.sendCommand) {
      return client.eval(READ_SCRIPT, 1, fullKey);
    }
    return client.eval(READ_SCRIPT, { keys: [fullKey], arguments: [] });
  }

  function parsePair(raw) {
    // Response shape: [count, ttl] but Upstash may return strings.
    const [countRaw, ttlRaw] = Array.isArray(raw) ? raw : [raw, -1];
    return { count: Number(countRaw), ttl: Number(ttlRaw) };
  }

  return {
    async get(key) {
      const { count, ttl } = parsePair(await runRead(k(key)));
      if (!Number.isFinite(count) || count <= 0 || ttl < 0) {
        return null;
      }
      return { count, expiresAt: Date.now() + ttl };
    },

    async read(key) {
      const { count, ttl } = parsePair(await runRead(k(key)));
      if (!Number.isFinite(count) || count <= 0 || ttl < 0) {
        return null;
      }
      return { count, expiresAt: Date.now() + ttl };
    },

    async incr(key, ttlMs) {
      const { count, ttl } = parsePair(await runIncr(k(key), ttlMs));
      return { count, expiresAt: Date.now() + (ttl > 0 ? ttl : ttlMs) };
    },

    async set(key, count, ttlMs) {
      // node-redis v4 accepts positional 'PX', ttl on its `set` command;
      // ioredis and Upstash do too.
      await client.set(k(key), String(count), 'PX', ttlMs);
    },

    async delete(key) {
      await client.del(k(key));
    },

    async reset(key) {
      await client.del(k(key));
    },
  };
}
