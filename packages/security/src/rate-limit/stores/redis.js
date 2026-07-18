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

// Returns the raw stored value + TTL. Do NOT coerce with `tonumber` in
// Lua — `read()` and `get()` share this script, and bucket-algorithm
// state is a compact string like `'4.5|1234567890'` that Lua would
// silently turn into `nil`. The JS wrapper coerces where numeric.
const READ_SCRIPT = `
local key = KEYS[1]
local current = redis.call('GET', key)
if not current then
  return { false, -1 }
end
local ttl = redis.call('PTTL', key)
if ttl < 0 then
  ttl = 0
end
return { current, ttl }
`.trim();

// Exists-guarded DECR: a rollback must never create the key (a plain DECR
// on a missing key would mint a TTL-less `-1` that leaks forever) and
// never take the counter negative.
const DECR_SCRIPT = `
local key = KEYS[1]
if redis.call('EXISTS', key) == 0 then
  return 0
end
local count = redis.call('DECR', key)
if count < 0 then
  redis.call('SET', key, '0', 'KEEPTTL')
  return 0
end
return count
`.trim();

// Compare-and-set for the bucket algorithms' opaque state strings. The
// sentinel below means "key must not exist" — bucket state is always
// '<int>|<int>', so it can never collide with a real value.
const CAS_ABSENT = '__absent__';
const CAS_SCRIPT = `
local key = KEYS[1]
local expected = ARGV[1]
local value = ARGV[2]
local ttl = tonumber(ARGV[3])
local current = redis.call('GET', key)
if expected == '${CAS_ABSENT}' then
  if current then
    return 0
  end
else
  if not current or current ~= expected then
    return 0
  end
end
redis.call('SET', key, value, 'PX', ttl)
return 1
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
    if (typeof client.exortekRlDecr !== 'function') {
      client.defineCommand('exortekRlDecr', { numberOfKeys: 1, lua: DECR_SCRIPT });
    }
    if (typeof client.exortekRlCas !== 'function') {
      client.defineCommand('exortekRlCas', { numberOfKeys: 1, lua: CAS_SCRIPT });
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

  async function runDecr(fullKey) {
    if (useDefined) {
      return client.exortekRlDecr(fullKey);
    }
    if (client.eval.length >= 2 && !client.sendCommand) {
      return client.eval(DECR_SCRIPT, 1, fullKey);
    }
    return client.eval(DECR_SCRIPT, { keys: [fullKey], arguments: [] });
  }

  async function runCas(fullKey, expected, value, ttlMs) {
    if (useDefined) {
      return client.exortekRlCas(fullKey, expected, value, ttlMs);
    }
    if (client.eval.length >= 2 && !client.sendCommand) {
      return client.eval(CAS_SCRIPT, 1, fullKey, expected, value, ttlMs);
    }
    return client.eval(CAS_SCRIPT, { keys: [fullKey], arguments: [expected, String(value), String(ttlMs)] });
  }

  function parsePair(raw) {
    // Response shape: [count, ttl] but Upstash may return strings.
    const [countRaw, ttlRaw] = Array.isArray(raw) ? raw : [raw, -1];
    return { count: Number(countRaw), ttl: Number(ttlRaw) };
  }

  return {
    // `get` is called by both numeric callers (sliding, with-ban) and
    // bucket algorithms whose state is an opaque string like
    // `'4.5|1234567890'`. Coerce to `Number` for pure integer values
    // only — anything else passes through as the raw string so the
    // CAS loop in tokenBucket / leakyBucket keeps working.
    async get(key) {
      const raw = await runRead(k(key));
      const [countRaw, ttlRaw] = Array.isArray(raw) ? raw : [raw, -1];
      const ttl = Number(ttlRaw);
      if (countRaw === null || countRaw === undefined || countRaw === false || ttl < 0) {
        return null;
      }
      const count = /^-?\d+$/.test(String(countRaw)) ? Number(countRaw) : countRaw;
      return { count, expiresAt: Date.now() + ttl };
    },

    // `read` is called by fixed / sliding which persist their state as
    // an integer counter (from INCR). Numeric parsing is correct here.
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

    async decr(key) {
      await runDecr(k(key));
    },

    async compareAndSet(key, expected, value, ttlMs) {
      const raw = await runCas(k(key), expected === null ? CAS_ABSENT : String(expected), String(value), ttlMs);
      return Number(raw) === 1;
    },

    async delete(key) {
      await client.del(k(key));
    },

    async reset(key) {
      await client.del(k(key));
    },
  };
}
