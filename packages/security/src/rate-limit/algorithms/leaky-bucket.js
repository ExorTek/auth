import { assertBucketOptions, assertKey } from '../options.js';

/**
 * Leaky-bucket rate limiter.
 *
 * The bucket accumulates requests up to `capacity`. Water leaks out at a
 * constant `leakRate` requests/second — the effective steady-state rate.
 * When the bucket is full, incoming requests are rejected. Unlike
 * token-bucket, there is **no burst tolerance**: outgoing rate is
 * strictly bounded by `leakRate`.
 *
 * Use for traffic shaping and protecting downstream services with a hard
 * throughput ceiling (SMTP relays, upstream APIs with quota-per-second).
 * For user-facing endpoints, prefer `sliding` or `tokenBucket`.
 *
 * State encoding matches token-bucket: `"<level*1000>|<updatedAt>"`.
 *
 * @param {import('../index.js').BucketLimiterConfig} config
 * @returns {import('../index.js').Limiter}
 */
export function leakyBucket(config) {
  assertBucketOptions(config, 'leakyBucket');
  const capacity = config.capacity;
  const leakRate = config.leakRate; // requests / second
  const store = config.store;
  const ttlMs = Math.max(60_000, Math.ceil((capacity / leakRate) * 1000 * 4));

  return {
    async check(input) {
      assertKey(input);
      const { key } = input;
      const storeKey = `lb:${key}`;
      const now = Date.now();

      const raw = await store.get(storeKey);
      let level = 0;
      let updatedAt = now;
      if (raw && raw.count !== null && raw.count !== undefined) {
        const parsed = decodeState(raw.count);
        if (parsed) {
          level = parsed.level;
          updatedAt = parsed.updatedAt;
        }
      }

      const elapsedSec = Math.max(0, (now - updatedAt) / 1000);
      level = Math.max(0, level - elapsedSec * leakRate);

      if (level + 1 > capacity) {
        const overflow = level + 1 - capacity;
        const retryAfter = Math.max(1, Math.ceil(overflow / leakRate));
        await persist(store, storeKey, level, now, ttlMs);
        return {
          allowed: false,
          remaining: 0,
          reset: new Date(now + retryAfter * 1000),
          retryAfter,
        };
      }

      level += 1;
      await persist(store, storeKey, level, now, ttlMs);

      const secondsUntilEmpty = level / leakRate;
      return {
        allowed: true,
        remaining: Math.floor(capacity - level),
        reset: new Date(now + secondsUntilEmpty * 1000),
        retryAfter: null,
      };
    },
  };
}

async function persist(store, key, level, updatedAt, ttlMs) {
  await store.set(key, encodeState(level, updatedAt), ttlMs);
}

function encodeState(level, updatedAt) {
  return `${Math.round(level * 1000)}|${updatedAt}`;
}

function decodeState(raw) {
  const s = String(raw);
  const bar = s.indexOf('|');
  if (bar <= 0) {
    return null;
  }
  const levelMilli = Number(s.slice(0, bar));
  const updatedAt = Number(s.slice(bar + 1));
  if (!Number.isFinite(levelMilli) || !Number.isFinite(updatedAt)) {
    return null;
  }
  return { level: levelMilli / 1000, updatedAt };
}
