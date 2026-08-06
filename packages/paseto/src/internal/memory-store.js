/**
 * In-process refresh-token registry with configurable GC.
 *
 * A thin binding over `@exortek/shared/registry-store` — the Map-backed
 * implementation, expiry-on-read, and the `interval` / `lazy` / `lru` GC
 * strategies all live there. This file supplies paseto's error class and
 * its duration parser, and declares the public store types locally so the
 * emitted `.d.ts` stays self-contained (no reference to the private,
 * never-published `@exortek/shared`).
 *
 *   - `interval` (default) — periodic sweep of expired entries.
 *   - `lazy` — no sweep; expired entries linger until queried.
 *   - `lru` — `interval` plus a `maxSize` cap; oldest-inserted evicted.
 *     Never use `lru` for a revocation registry — eviction silently
 *     un-revokes.
 */

import { createMemoryRegistryStore } from '@exortek/shared/registry-store';

import { PasetoError, ErrorCode } from './errors.js';
import { parseDurationSeconds } from './duration.js';

/**
 * @typedef {Object} StoreRecord
 * @property {number} expiresAt
 * @property {Record<string, unknown>} [metadata]
 *
 * @typedef {Object} MarkUsedResult
 * @property {boolean} swapped
 * @property {StoreRecord} record
 *
 * @typedef {Object} Store
 * @property {(key: string, expiresAt: number, metadata?: Record<string, unknown>) => Promise<void>} add
 * @property {(key: string) => Promise<boolean>} has
 * @property {(key: string) => Promise<StoreRecord | null>} get
 * @property {(key: string) => Promise<void>} delete
 * @property {(filter: Record<string, unknown>) => Promise<number>} deleteAll
 * @property {(key: string, nowSec: number) => Promise<MarkUsedResult | null>} [markUsed]
 * @property {() => number} size
 * @property {() => void} _stop
 *
 * @typedef {Object} MemoryConfig
 * @property {number} [maxSize]
 * @property {{ strategy?: 'interval' | 'lazy' | 'lru', interval?: string | number, maxSize?: number }} [gc]
 */

/**
 * @param {MemoryConfig} [options]
 * @returns {Store}
 */
export function createMemoryStore(options) {
  return createMemoryRegistryStore(
    { StoreError: PasetoError, storeErrorCode: ErrorCode.STORE_ERROR, parseIntervalSeconds: parseDurationSeconds },
    options,
  );
}
