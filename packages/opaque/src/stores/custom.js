/**
 * Wrap a user-supplied store into the `OpaqueStore` interface. Validates the
 * required methods at construction time (not on first use) and promotes sync
 * implementations to the async interface.
 *
 * Required: `set(key, value, options?)`, `get(key)`, `delete(key)`.
 *
 * @param {Partial<import('../index.js').OpaqueStore>} impl
 * @returns {import('../index.js').OpaqueStore}
 */
import { createCustomStoreValidator } from '@exortek/shared/custom-store';
import { invalidArgument } from '../internal/guards.js';

export const customStore = createCustomStoreValidator({
  required: ['set', 'get', 'delete'],
  wrap: invalidArgument,
  // Coerce `set` to void — a native Map.set returns the Map, which would
  // otherwise leak out as Promise<Map> and break the OpaqueStore type.
  coerce: { set: () => undefined },
});
