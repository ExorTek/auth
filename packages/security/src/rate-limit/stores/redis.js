import { SecurityError, ErrorCode } from '../../internal/errors.js';

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
 * Atomicity: `incr` uses a single EVAL Lua script that INCR's the key and
 * sets PEXPIRE only when the key is fresh (count == 1). This means the TTL
 * anchors to the first increment in the window — the correct semantics for
 * fixed / token-bucket algorithms. The sliding-window algorithm anchors
 * its own timestamp keys and doesn't need this behavior.
 *
 * Namespacing: every key is prefixed with `rl:` by default so this adapter
 * doesn't collide with your application keys. Configurable via `prefix`.
 */
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
  const k = (key) => `${prefix}${key}`;

  async function evalScript(script, keys, args) {
    // node-redis and Upstash accept `client.eval(script, { keys, arguments })`
    // ioredis accepts `client.eval(script, keys.length, ...keys, ...args)`
    // We detect ioredis by the numeric-arity signature — it's the older API.
    // Both clients ship the same `EVAL` semantics on the wire.
    if (client.eval.length >= 2 && !client.sendCommand) {
      // Best-effort: ioredis path
      return client.eval(script, keys.length, ...keys, ...args);
    }
    return client.eval(script, { keys, arguments: args.map(String) });
  }

  return {
    async get(key) {
      const [countStr, pttlStr] = await Promise.all([
        client.get(k(key)),
        client.pttl ? client.pttl(k(key)) : Promise.resolve(-1),
      ]);
      if (countStr === null || countStr === undefined) {
        return null;
      }
      const count = Number(countStr);
      const pttl = Number(pttlStr);
      if (!Number.isFinite(count) || pttl < 0) {
        return null;
      }
      return { count, expiresAt: Date.now() + pttl };
    },

    async incr(key, ttlMs) {
      const raw = await evalScript(INCR_SCRIPT, [k(key)], [ttlMs]);
      // Response shape: [count, pttl] — but Upstash may return strings.
      const [countRaw, pttlRaw] = Array.isArray(raw) ? raw : [raw, ttlMs];
      const count = Number(countRaw);
      const pttl = Number(pttlRaw);
      return { count, expiresAt: Date.now() + (pttl > 0 ? pttl : ttlMs) };
    },

    async set(key, count, ttlMs) {
      // node-redis v4 uses options object; ioredis uses positional 'PX', ttl.
      // Both accept the positional form as of current versions.
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
