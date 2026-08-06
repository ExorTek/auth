/**
 * In-process blacklist / refresh-token store with configurable GC.
 *
 * A thin binding over `@exortek/shared/registry-store` — the Map-backed
 * implementation, expiry-on-read, and the `interval` / `lazy` / `lru` GC
 * strategies all live there. This file supplies jwt's error class and its
 * duration parser.
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
 * @typedef {import('@exortek/shared/registry-store').StoreRecord} StoreRecord
 * @typedef {import('@exortek/shared/registry-store').MarkUsedResult} MarkUsedResult
 * @typedef {import('@exortek/shared/registry-store').Store} Store
 * @typedef {import('@exortek/shared/registry-store').MemoryConfig} MemoryConfig
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
