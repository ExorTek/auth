import { isFunction } from '@exortek/shared/predicates';

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
 * Because token accounting is more than a simple counter, this reads the
 * state, recomputes, and writes it back. When the store exposes the
 * optional atomic `compareAndSet` (the bundled memory and Redis stores
 * both do), the write is a CAS retried on contention — concurrent
 * requests can never double-spend a token. Stores without it fall back
 * to a last-writer-wins `set`, which can race under concurrency.
 *
 * @param {import('../index.js').BucketLimiterConfig} config
 * @returns {import('../index.js').Limiter}
 */
export function tokenBucket(config) {
  assertBucketOptions(config, 'tokenBucket');
  const capacity = config.capacity;
  const refillRate = config.refillRate; // tokens / second
  const store = config.store;
  // Keep state for at least a full refill cycle after last write so idle
  // callers don't lose their history under LRU pressure.
  const ttlMs = Math.max(60_000, Math.ceil((capacity / refillRate) * 1000 * 4));

  const hasCas = isFunction(store.compareAndSet);
  // Optimistic-concurrency bound. A failed CAS means another request's
  // write landed — so every retry round makes system-wide progress and the
  // loop terminates in at most <contenders> rounds (lock-free). The cap
  // only guards against a broken store whose CAS never succeeds; when it
  // trips, we FAIL CLOSED (deny) rather than fall back to a racy `set` —
  // an unconditional write here would be exactly the double-spend the CAS
  // exists to prevent.
  const MAX_ATTEMPTS = 32;

  return {
    async check(input) {
      assertKey(input);
      const { key } = input;
      const storeKey = `tb:${key}`;

      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        const now = Date.now();
        const raw = await store.get(storeKey);
        const rawState = raw && raw.count !== null && raw.count !== undefined ? String(raw.count) : null;
        let tokens = capacity;
        let updatedAt = now;
        if (rawState !== null) {
          const parsed = decodeState(rawState);
          if (parsed) {
            tokens = parsed.tokens;
            updatedAt = parsed.updatedAt;
          }
        }

        const elapsedSec = Math.max(0, (now - updatedAt) / 1000);
        tokens = Math.min(capacity, tokens + elapsedSec * refillRate);

        let nextState;
        let result;
        if (tokens < 1) {
          const deficitTokens = 1 - tokens;
          const retryAfter = Math.max(1, Math.ceil(deficitTokens / refillRate));
          nextState = encodeState(tokens, now);
          result = {
            allowed: false,
            remaining: 0,
            reset: new Date(now + retryAfter * 1000),
            retryAfter,
          };
        } else {
          tokens -= 1;
          nextState = encodeState(tokens, now);
          const secondsUntilFull = (capacity - tokens) / refillRate;
          result = {
            allowed: true,
            remaining: Math.floor(tokens),
            reset: new Date(now + secondsUntilFull * 1000),
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
