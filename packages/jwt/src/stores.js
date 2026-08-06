/**
 * Store adapters for the blacklist / refresh-token registry. Ships two
 * built-in backends (`memory`, `redis`) and a `custom` factory that
 * accepts the caller's own implementation of the {@link Store} shape.
 *
 * Subpath entry (`@exortek/jwt/stores`).
 */

import { assertStoreShape } from '@exortek/shared/custom-store';
import { createMemoryStore } from './internal/memory-store.js';
import { createRedisStore } from './internal/redis-store.js';
import { invalidArgument } from './internal/guards.js';

// Core blacklist contract every custom impl must satisfy. `markUsed` is only
// exercised by refresh-token rotation, so a blacklist-only store may omit it.
const CUSTOM_STORE_REQUIRED = ['add', 'has', 'get', 'delete', 'deleteAll'];

/**
 * @typedef {import('./internal/memory-store.js').Store} Store
 *
 * @typedef {Object} MemoryConfig
 * @property {number} [maxSize]
 * @property {{ strategy?: 'interval' | 'lazy' | 'lru', interval?: string | number, maxSize?: number }} [gc]
 *
 * @typedef {Object} RedisConfig
 * @property {unknown} client            ioredis or `redis@4` client
 * @property {string} [keyPrefix]
 *
 * @typedef {Object} CustomConfig
 * @property {Store} impl                 caller's own store implementation
 */

/**
 * @overload
 * @param {'memory'} kind
 * @param {MemoryConfig} [options]
 * @returns {Store}
 *
 * @overload
 * @param {'redis'} kind
 * @param {RedisConfig} options
 * @returns {Store}
 *
 * @overload
 * @param {'custom'} kind
 * @param {CustomConfig} options
 * @returns {Store}
 *
 * @param {'memory' | 'redis' | 'custom'} kind
 * @param {MemoryConfig | RedisConfig | CustomConfig} [options]
 * @returns {Store}
 */
export function createStore(kind, options) {
  switch (kind) {
    case 'memory':
      return createMemoryStore(/** @type {MemoryConfig} */ (options));
    case 'redis':
      return createRedisStore(/** @type {RedisConfig} */ (options));
    case 'custom': {
      const cfg = /** @type {CustomConfig} */ (options) ?? {};
      assertStoreShape(cfg.impl, CUSTOM_STORE_REQUIRED, invalidArgument);
      return cfg.impl;
    }
    default:
      throw invalidArgument(
        `createStore.kind: unknown kind ${JSON.stringify(kind)} — expected 'memory' | 'redis' | 'custom'`,
      );
  }
}
