/**
 * In-process blacklist / refresh-token store with configurable GC.
 *
 * A thin binding over `@exortek/shared/registry-store` — the Map-backed
 * implementation, expiry-on-read, and the `interval` / `lazy` / `lru` GC
 * strategies all live there. This file supplies jwt's error class and its
 * duration parser, and declares the public store types locally so the
 * emitted `.d.ts` stays self-contained (no reference to the private,
 * never-published `@exortek/shared`).
 *
 *   - `interval` (default) — a periodic sweep drops expired entries;
 *     safe under high churn but wakes the event loop at fixed cadence.
 *   - `lazy` — no sweep; expired entries linger in the map until they
 *     are queried. Zero background CPU.
 *   - `lru` — like `interval` but with a `maxSize` cap; the
 *     least-recently-added record is evicted when the cap is reached.
 *     WARNING: never use `lru` as a revocation blacklist — eviction
 *     silently un-revokes tokens whose entry got dropped for capacity.
 */

import { createMemoryRegistryStore } from '@exortek/shared/registry-store';

import { JwtError, ErrorCode } from './errors.js';
import { parseDuration } from './duration.js';

/**
 * @typedef {Object} StoreRecord
 * @property {number} expiresAt
 * @property {Record<string, unknown>} [metadata]
 *
 * @typedef {Object} MarkUsedResult
 * @property {boolean} swapped       true if this call stamped usedAt (was null before)
 * @property {StoreRecord} record    the record after the operation
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
    { StoreError: JwtError, storeErrorCode: ErrorCode.STORE_ERROR, parseIntervalSeconds: parseDuration },
    options,
  );
}
