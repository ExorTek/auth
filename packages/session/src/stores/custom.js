/**
 * Wrap a user-supplied store into the `SessionStore` interface. Validates the
 * required methods at construction time (not on first use) and promotes sync
 * implementations to the async interface.
 *
 * Required: `get`, `put`, `update`, `revoke`, `revokeAllForUser`,
 * `revokeAllExcept`, `listByUser`, `countActive`.
 * Optional: `_stop` — wrapped verbatim (a sync cleanup, not promisified).
 *
 * @param {Partial<import('./memory.js').SessionStore>} impl
 * @returns {import('./memory.js').SessionStore}
 */
import { isFunction } from '@exortek/shared/predicates';
import { createCustomStoreValidator } from '@exortek/shared/custom-store';
import { invalidArgument } from '../internal/guards.js';

const validate = createCustomStoreValidator({
  required: ['get', 'put', 'update', 'revoke', 'revokeAllForUser', 'revokeAllExcept', 'listByUser', 'countActive'],
  wrap: invalidArgument,
});

export function customStore(impl) {
  const store = validate(impl);
  // `_stop` clears a sweep timer; keep it a synchronous fire-and-forget rather
  // than promoting it to a Promise like the data methods.
  if (isFunction(impl._stop)) {
    store._stop = () => impl._stop();
  }
  return store;
}
