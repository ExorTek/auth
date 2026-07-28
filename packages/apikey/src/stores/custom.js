/**
 * Wrap a user-supplied store into the `ApiKeyStore` interface.
 * Validates that the required methods exist so a misconfiguration
 * surfaces at construction time, not on the first `createApiKey` /
 * `verifyApiKey` call. Sync implementations are wrapped transparently
 * — return a plain value or a Promise, either works.
 *
 * Required: `put`, `getById`, `update`, `revoke`, `revokeAllForUser`, `listByUser`.
 *
 * @param {Partial<import('../index.js').ApiKeyStore>} impl
 * @returns {import('../index.js').ApiKeyStore}
 */
import { isObject, isFunction } from '@exortek/shared/predicates';
import { invalidArgument } from '../internal/guards.js';

const REQUIRED = ['put', 'getById', 'update', 'revoke', 'revokeAllForUser', 'listByUser'];

export function customStore(impl) {
  if (!isObject(impl)) {
    throw invalidArgument(`customStore(impl) requires an object with { ${REQUIRED.join(', ')} } methods`);
  }
  for (const name of REQUIRED) {
    if (!isFunction(impl[name])) {
      throw invalidArgument(`customStore: impl.${name} is required and must be a function`);
    }
  }
  return {
    put: record => Promise.resolve(impl.put(record)),
    getById: id => Promise.resolve(impl.getById(id)),
    update: (id, patch) => Promise.resolve(impl.update(id, patch)),
    revoke: (id, reason) => Promise.resolve(impl.revoke(id, reason)),
    revokeAllForUser: (userId, reason) => Promise.resolve(impl.revokeAllForUser(userId, reason)),
    listByUser: userId => Promise.resolve(impl.listByUser(userId)),
  };
}
