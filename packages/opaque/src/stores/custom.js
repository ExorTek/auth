/**
 * Wrap a user-supplied store into the `OpaqueStore` interface.
 * Validates that the required methods exist so a misconfiguration
 * surfaces at construction time, not on the first `create`/`verify`
 * call. Sync implementations are wrapped transparently — return a
 * plain value or a Promise, either works.
 *
 * Required: `set(key, value, options?)`, `get(key)`, `delete(key)`.
 *
 * @param {Partial<import('../index.js').OpaqueStore>} impl
 * @returns {import('../index.js').OpaqueStore}
 */
import { isObject, isFunction } from '@exortek/shared/predicates';
import { invalidArgument } from '../internal/guards.js';

const REQUIRED = ['set', 'get', 'delete'];

export function customStore(impl) {
  if (!isObject(impl)) {
    throw invalidArgument('customStore(impl) requires an object with { set, get, delete } methods');
  }
  for (const name of REQUIRED) {
    if (!isFunction(impl[name])) {
      throw invalidArgument(`customStore: impl.${name} is required and must be a function`);
    }
  }
  return {
    // Coerce to void — a native Map.set returns the Map, which would
    // otherwise leak out as Promise<Map>, breaking the OpaqueStore type.
    set: (key, value, options) => Promise.resolve(impl.set(key, value, options)).then(() => undefined),
    get: key => Promise.resolve(impl.get(key)),
    delete: key => Promise.resolve(impl.delete(key)),
  };
}
