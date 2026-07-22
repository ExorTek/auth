/**
 * Store implementations shipped with `@exortek/challenge`. Any object
 * exposing the {@link IncrStore} shape works — these are provided as
 * a zero-config default (memory) and a cluster-safe default (Redis).
 * `@exortek/security`'s rate-limit stores are wire-compatible.
 */

export { memoryStore } from './memory.js';
export { redisStore } from './redis.js';

/**
 * @typedef {object} IncrStore
 * @property {(key: string, ttlMs: number) => Promise<{ count: number, expiresAt?: number }>} incr
 *   Atomic increment-with-expiry. First call for a fresh key returns
 *   `{ count: 1 }` and arms a TTL of `ttlMs`; subsequent calls before
 *   expiry return the incremented count. `verifyChallenge` reads
 *   `count > 1` as "already consumed".
 */
