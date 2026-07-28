/**
 * Wrap a user-supplied store into the `SessionStore` interface.
 * Validates that the required methods exist so a misconfiguration
 * surfaces at construction time, not on the first `issue`/`verify`
 * call. Sync implementations are wrapped transparently — return a
 * plain value or a Promise, either works.
 *
 * Required: `get`, `put`, `update`, `revoke`, `revokeAllForUser`,
 * `revokeAllExcept`, `listByUser`, `countActive`.
 * Optional (only wrapped through when present): `_stop`.
 *
 * @param {Partial<import('./memory.js').SessionStore>} impl
 * @returns {import('./memory.js').SessionStore}
 */
import { isObject, isFunction } from '@exortek/shared/predicates';
import { invalidArgument } from '../internal/guards.js';

const REQUIRED = ['get', 'put', 'update', 'revoke', 'revokeAllForUser', 'revokeAllExcept', 'listByUser', 'countActive'];

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
    get: sid => Promise.resolve(impl.get(sid)),
    put: record => Promise.resolve(impl.put(record)),
    update: (sid, patch) => Promise.resolve(impl.update(sid, patch)),
    revoke: (sid, reason) => Promise.resolve(impl.revoke(sid, reason)),
    revokeAllForUser: (uid, reason) => Promise.resolve(impl.revokeAllForUser(uid, reason)),
    revokeAllExcept: (uid, keepSid, reason) => Promise.resolve(impl.revokeAllExcept(uid, keepSid, reason)),
    listByUser: uid => Promise.resolve(impl.listByUser(uid)),
    countActive: uid => Promise.resolve(impl.countActive(uid)),
  };
  if (isFunction(impl._stop)) {
    store._stop = () => impl._stop();
  }
  return store;
}
