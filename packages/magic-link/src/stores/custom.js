/**
 * Wrap a user-supplied store into the `MagicLinkStore` interface. Validates
 * the required methods at construction time (not on first use) and promotes
 * sync implementations to the async interface.
 *
 * Required: `put`, `getById`, `consume`.
 * Optional (only wrapped through when present): `incrRate` (required by
 * `maxPerEmail`), `listByEmail` / `revokeByEmail` (required by
 * `listPendingForEmail` / `revokeAllForEmail`).
 *
 * @param {Partial<import('../index.js').MagicLinkStore>} impl
 * @returns {import('../index.js').MagicLinkStore}
 */
import { createCustomStoreValidator } from '@exortek/shared/custom-store';
import { invalidArgument } from '../internal/guards.js';

export const customStore = createCustomStoreValidator({
  required: ['put', 'getById', 'consume'],
  optional: ['incrRate', 'listByEmail', 'revokeByEmail'],
  wrap: invalidArgument,
});
