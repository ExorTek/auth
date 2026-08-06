/**
 * Wrap a user-supplied store into the `ApiKeyStore` interface. Validates the
 * required methods at construction time (not on first use) and promotes sync
 * implementations to the async interface.
 *
 * Required: `put`, `getById`, `update`, `revoke`, `revokeAllForUser`, `listByUser`.
 *
 * @param {Partial<import('../index.js').ApiKeyStore>} impl
 * @returns {import('../index.js').ApiKeyStore}
 */
import { createCustomStoreValidator } from '@exortek/shared/custom-store';
import { invalidArgument } from '../internal/guards.js';

export const customStore = createCustomStoreValidator({
  required: ['put', 'getById', 'update', 'revoke', 'revokeAllForUser', 'listByUser'],
  wrap: invalidArgument,
});
