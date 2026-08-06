/**
 * Redis-backed blacklist / refresh-token store.
 *
 * A thin binding over `@exortek/shared/registry-store` — the ioredis /
 * redis@4 dialect handling, native `EX` TTL, `SCAN`-based `deleteAll`, and
 * the atomic `markUsed` Lua all live there. This file supplies jwt's error
 * class and default key prefix.
 */

import { createRedisRegistryStore } from '@exortek/shared/registry-store';

import { JwtError, ErrorCode } from './errors.js';

/**
 * @typedef {import('@exortek/shared/registry-store').Store} Store
 *
 * @typedef {Object} RedisConfig
 * @property {any} client        ioredis or redis@4 client
 * @property {string} [keyPrefix]
 * @property {'ioredis' | 'node-redis'} [dialect]
 *   Override auto-detection for wrapped/proxied clients whose
 *   `constructor.name` doesn't match the underlying driver.
 */

/**
 * @param {RedisConfig} options
 * @returns {Store}
 */
export function createRedisStore(options) {
  return createRedisRegistryStore(
    { StoreError: JwtError, storeErrorCode: ErrorCode.STORE_ERROR, defaultKeyPrefix: 'jwt:bl:' },
    options,
  );
}
