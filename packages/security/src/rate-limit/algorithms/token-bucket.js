import { assertBucketOptions, assertKey } from '../options.js';

/**
 * Token-bucket rate limiter.
 *
 * A bucket of `capacity` tokens refills at `refillRate` tokens per second.
 * Every request consumes one token; if the bucket is empty, the request is
 * rejected. Allows *controlled burst* — an idle caller accumulates a full
 * bucket and can spend it at once, then drops to the steady rate.
 *
 * State is stored as a single JSON blob per key: `{ tokens, updatedAt }`.
 * Tokens are recomputed on read from the elapsed time — no background
 * timer needed.
 *
 * Because token accounting is more than a simple counter, this uses
 * `store.get` + `store.set` rather than `incr`. Two concurrent requests
 * on the same key can race; if you need hard atomicity across a cluster,
 * back this with a Redis store where the adapter can be extended with a
 * bucket-specific Lua script (out of scope for v1 — memory + custom is
 * atomic enough for most workloads).
 *
 * @param {{ capacity: number, refillRate: number, store: object }} config
 */
export function tokenBucket(config) {
  assertBucketOptions(config, 'tokenBucket');
  const capacity = config.capacity;
  const refillRate = config.refillRate; // tokens / second
  const store = config.store;
  // Keep state for at least a full refill cycle after last write so idle
  // callers don't lose their history under LRU pressure.
  const ttlMs = Math.max(60_000, Math.ceil((capacity / refillRate) * 1000 * 4));

  return {
    async check(input) {
      assertKey(input);
      const { key } = input;
      const storeKey = `tb:${key}`;
      const now = Date.now();

      const raw = await store.get(storeKey);
      let tokens = capacity;
      let updatedAt = now;
      if (raw && raw.count !== null && raw.count !== undefined) {
        const parsed = decodeState(raw.count);
        if (parsed) {
          tokens = parsed.tokens;
          updatedAt = parsed.updatedAt;
        }
      }

      const elapsedSec = Math.max(0, (now - updatedAt) / 1000);
      tokens = Math.min(capacity, tokens + elapsedSec * refillRate);

      if (tokens < 1) {
        const deficitTokens = 1 - tokens;
        const retryAfter = Math.max(1, Math.ceil(deficitTokens / refillRate));
        await persist(store, storeKey, tokens, now, ttlMs);
        return {
          allowed: false,
          remaining: 0,
          reset: new Date(now + retryAfter * 1000),
          retryAfter,
        };
      }

      tokens -= 1;
      await persist(store, storeKey, tokens, now, ttlMs);

      const secondsUntilFull = (capacity - tokens) / refillRate;
      return {
        allowed: true,
        remaining: Math.floor(tokens),
        reset: new Date(now + secondsUntilFull * 1000),
        retryAfter: null,
      };
    },
  };
}

async function persist(store, key, tokens, updatedAt, ttlMs) {
  await store.set(key, encodeState(tokens, updatedAt), ttlMs);
}

// Bucket state is a compact string so it survives any store that treats
// `count` as an opaque scalar: `"<tokens>|<updatedAt>"`. Two integers,
// pipe-delimited, no JSON overhead.
function encodeState(tokens, updatedAt) {
  return `${Math.round(tokens * 1000)}|${updatedAt}`;
}

function decodeState(raw) {
  const s = String(raw);
  const bar = s.indexOf('|');
  if (bar <= 0) {
    return null;
  }
  const tokensMilli = Number(s.slice(0, bar));
  const updatedAt = Number(s.slice(bar + 1));
  if (!Number.isFinite(tokensMilli) || !Number.isFinite(updatedAt)) {
    return null;
  }
  return { tokens: tokensMilli / 1000, updatedAt };
}
