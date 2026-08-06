/**
 * In-process refresh-token registry with configurable GC.
 *
 * A thin binding over `@exortek/shared/registry-store` — the Map-backed
 * implementation, expiry-on-read, and the `interval` / `lazy` / `lru` GC
 * strategies all live there. This file supplies paseto's error class and
 * its duration parser.
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
    { StoreError: PasetoError, storeErrorCode: ErrorCode.STORE_ERROR, parseIntervalSeconds: parseDurationSeconds },
    options,
  );
}
