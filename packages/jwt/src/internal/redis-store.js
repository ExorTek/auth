/**
 * Redis-backed blacklist / refresh-token store using native TTL for GC.
 * Compatible with both `ioredis` and `redis@4`. Scaffold stub.
 */

import { JwtError, ErrorCode } from './errors.js';

/**
 * @typedef {import('./memory-store.js').Store} Store
 *
 * @param {{ client: unknown, keyPrefix?: string }} [_options]
 * @returns {Store}
 */
export function createRedisStore(_options) {
  throw new JwtError(ErrorCode.STORE_ERROR, 'redis-store.createRedisStore: not implemented');
}
