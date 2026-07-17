/**
 * In-process blacklist / refresh-token store with interval-based GC.
 * Scaffold stub. Implementation lands in the stores commit.
 */

import { JwtError, ErrorCode } from './errors.js';

/**
 * @typedef {Object} StoreRecord
 * @property {number} expiresAt      unix seconds
 * @property {Record<string, unknown>} [metadata]
 *
 * @typedef {Object} Store
 * @property {(key: string, expiresAt: number, metadata?: Record<string, unknown>) => Promise<void>} add
 * @property {(key: string) => Promise<boolean>} has
 * @property {(key: string) => Promise<StoreRecord | null>} get
 * @property {(key: string) => Promise<void>} delete
 * @property {(filter: Record<string, unknown>) => Promise<number>} deleteAll
 */

/**
 * @param {{ maxSize?: number, gc?: { strategy?: 'interval' | 'lazy' | 'lru', interval?: string | number } }} [_options]
 * @returns {Store}
 */
export function createMemoryStore(_options) {
  throw new JwtError(ErrorCode.STORE_ERROR, 'memory-store.createMemoryStore: not implemented');
}
