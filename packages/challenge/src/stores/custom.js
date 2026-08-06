/**
 * Wrap a user-supplied store into the `IncrStore` interface. Validates that
 * `incr` exists at construction time (not on first use) and promotes a sync
 * implementation to the async interface.
 *
 * Required: `incr(key, ttlMs)`.
 *
 * @param {Partial<import('./index.js').IncrStore>} impl
 * @returns {import('./index.js').IncrStore}
 */
import { createCustomStoreValidator } from '@exortek/shared/custom-store';
import { invalidArgument } from '../internal/guards.js';

export const customStore = createCustomStoreValidator({
  required: ['incr'],
  wrap: invalidArgument,
});
