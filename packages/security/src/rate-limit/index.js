import { fixed } from './algorithms/fixed.js';
import { sliding } from './algorithms/sliding.js';
import { tokenBucket } from './algorithms/token-bucket.js';
import { leakyBucket } from './algorithms/leaky-bucket.js';
import { multi } from './multi.js';
import { memoryStore } from './stores/memory.js';
import { customStore } from './stores/custom.js';
import { redisStore } from './stores/redis.js';
import { withBan } from './with-ban.js';

/**
 * A store entry snapshot returned by `get` / `read` / `incr`.
 *
 * @typedef {object} StoreEntry
 * @property {number} count       Current counter value for the key.
 * @property {number} expiresAt   Absolute unix-ms timestamp when the key
 *                                stops being valid.
 */

/**
 * The store contract every rate-limit backend must satisfy.
 *
 * All methods are async. `incr` must be atomic across concurrent callers —
 * the algorithm layer relies on that guarantee.
 *
 * @typedef {object} RateLimitStore
 * @property {(key: string) => Promise<StoreEntry | null>} get
 *   Fetch current state. May refresh LRU position on stores that maintain one.
 * @property {(key: string) => Promise<StoreEntry | null>} read
 *   Non-mutating snapshot — does NOT refresh LRU / activity state.
 * @property {(key: string, ttlMs: number) => Promise<StoreEntry>} incr
 *   Atomically increment (or create) the key and return the new state.
 * @property {(key: string, count: number, ttlMs: number) => Promise<void>} set
 *   Overwrite (or create) the key with an explicit count and TTL.
 * @property {(key: string) => Promise<void>} delete
 * @property {(key: string) => Promise<void>} reset
 */

/**
 * @typedef {object} CheckInput
 * @property {string} key
 */

/**
 * @typedef {object} LimiterResult
 * @property {boolean} allowed
 * @property {number}  remaining
 * @property {Date | null} reset
 * @property {number | null} retryAfter
 */

/**
 * A composable limiter. Every algorithm and `multi()` returns this shape.
 *
 * @typedef {object} Limiter
 * @property {(input: CheckInput) => Promise<LimiterResult>} check
 */

/**
 * @typedef {object} WindowLimiterConfig
 * @property {number} requests
 * @property {string | number} window Duration string ('1m', '30s') or ms.
 * @property {RateLimitStore} store
 */

/**
 * @typedef {object} BucketLimiterConfig
 * @property {number} capacity
 * @property {number} [refillRate] Token-bucket only: tokens/second refill.
 * @property {number} [leakRate]   Leaky-bucket only: leak rate in req/sec.
 * @property {RateLimitStore} store
 */

/**
 * Public rate-limit surface.
 *
 * Algorithms:
 *   - `fixed({ requests, window, store })`         cheap, boundary bursts OK
 *   - `sliding({ requests, window, store })`       interpolated, recommended default
 *   - `tokenBucket({ capacity, refillRate, store })`   controlled burst
 *   - `leakyBucket({ capacity, leakRate, store })`     hard throughput cap
 *   - `multi({ limiters })`                        layered quotas (AND)
 *
 * Stores:
 *   - `stores.memory({ maxKeys, sweepMs })`        in-process (default)
 *   - `stores.custom(impl)`                        bring-your-own backend
 *   - `stores.redis(client, { prefix })`           ioredis/node-redis/Upstash
 */
export const rateLimit = {
  fixed,
  sliding,
  tokenBucket,
  leakyBucket,
  multi,
  withBan,
  stores: {
    memory: memoryStore,
    custom: customStore,
    redis: redisStore,
  },
};

export { fixed, sliding, tokenBucket, leakyBucket, multi, withBan };
export { memoryStore, customStore, redisStore };
