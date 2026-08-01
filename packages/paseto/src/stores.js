/**
 * Store adapters for the refresh-token registry used by the token-pair
 * layer. Ships two built-in backends (`memory`, `redis`) and a `custom`
 * factory that takes the caller's own implementation of the {@link Store}
 * shape.
 */

import { isObject } from '@exortek/shared/predicates';

import { createMemoryStore } from './internal/memory-store.js';
import { createRedisStore } from './internal/redis-store.js';
import { invalidArgument } from './internal/guards.js';

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
 * @property {'ioredis' | 'node-redis'} [dialect]
 *
 * @typedef {Object} CustomConfig
 * @property {Store} impl                 caller's own store implementation
 */

/**
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
      const cfg = /** @type {CustomConfig} */ (options);
      if (!cfg || !isObject(cfg.impl)) {
        throw invalidArgument('createStore("custom").options.impl must be a Store object');
      }
      return cfg.impl;
    }
    default:
      throw invalidArgument(
        `createStore.kind: unknown kind ${JSON.stringify(kind)} — expected 'memory' | 'redis' | 'custom'`,
      );
  }
}

export { createMemoryStore, createRedisStore };
