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
 * Writes go through the store's optional atomic `compareAndSet` when
 * available (bundled memory + Redis stores both provide it) so
 * concurrent requests can't race the level; stores without it fall
 * back to last-writer-wins `set`.
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

  const hasCas = typeof store.compareAndSet === 'function';
  // Same optimistic-concurrency loop as token-bucket — see that module for
  // the progress / fail-closed rationale.
  const MAX_ATTEMPTS = 32;

  return {
    async check(input) {
      assertKey(input);
      const { key } = input;
      const storeKey = `lb:${key}`;

      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        const now = Date.now();
        const raw = await store.get(storeKey);
        const rawState = raw && raw.count !== null && raw.count !== undefined ? String(raw.count) : null;
        let level = 0;
        let updatedAt = now;
        if (rawState !== null) {
          const parsed = decodeState(rawState);
          if (parsed) {
            level = parsed.level;
            updatedAt = parsed.updatedAt;
          }
        }

        const elapsedSec = Math.max(0, (now - updatedAt) / 1000);
        level = Math.max(0, level - elapsedSec * leakRate);

        let nextState;
        let result;
        if (level + 1 > capacity) {
          const overflow = level + 1 - capacity;
          const retryAfter = Math.max(1, Math.ceil(overflow / leakRate));
          nextState = encodeState(level, now);
          result = {
            allowed: false,
            remaining: 0,
            reset: new Date(now + retryAfter * 1000),
            retryAfter,
          };
        } else {
          level += 1;
          nextState = encodeState(level, now);
          const secondsUntilEmpty = level / leakRate;
          result = {
            allowed: true,
            remaining: Math.floor(capacity - level),
            reset: new Date(now + secondsUntilEmpty * 1000),
            retryAfter: null,
          };
        }

        if (hasCas) {
          const wrote = await store.compareAndSet(storeKey, rawState, nextState, ttlMs);
          if (!wrote) {
            continue; // lost the race — recompute on the fresh state
          }
        } else {
          await store.set(storeKey, nextState, ttlMs);
        }
        return result;
      }

      // CAS never succeeded across every attempt — only reachable with a
      // store whose compareAndSet is broken. Deny without writing state.
      return { allowed: false, remaining: 0, reset: new Date(Date.now() + 1000), retryAfter: 1 };
    },
  };
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
