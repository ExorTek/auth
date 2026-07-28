/**
 * Wrap a user-supplied store into the `MagicLinkStore` interface.
 * Validates that the required methods exist so a misconfiguration
 * surfaces at construction time, not on the first `createMagicLink` /
 * `verifyMagicLink` call. Sync implementations are wrapped
 * transparently — return a plain value or a Promise, either works.
 *
 * Required: `put`, `getById`, `consume`.
 * Optional (only wrapped through when present): `incrRate`
 * (required by `maxPerEmail`), `listByEmail` / `revokeByEmail`
 * (required by `listPendingForEmail` / `revokeAllForEmail`).
 *
 * @param {Partial<import('../index.js').MagicLinkStore>} impl
 * @returns {import('../index.js').MagicLinkStore}
 */
import { isObject, isFunction } from '@exortek/shared/predicates';
import { invalidArgument } from '../internal/guards.js';

const REQUIRED = ['put', 'getById', 'consume'];
const OPTIONAL = ['incrRate', 'listByEmail', 'revokeByEmail'];

export function customStore(impl) {
  if (!isObject(impl)) {
    throw invalidArgument(`customStore(impl) requires an object with { ${REQUIRED.join(', ')} } methods`);
  }
  for (const name of REQUIRED) {
    if (!isFunction(impl[name])) {
      throw invalidArgument(`customStore: impl.${name} is required and must be a function`);
    }
  }

  const store = {
    put: record => Promise.resolve(impl.put(record)),
    getById: id => Promise.resolve(impl.getById(id)),
    consume: id => Promise.resolve(impl.consume(id)),
  };
  for (const name of OPTIONAL) {
    if (isFunction(impl[name])) {
      store[name] = (...args) => Promise.resolve(impl[name](...args));
    }
  }
  return store;
}
