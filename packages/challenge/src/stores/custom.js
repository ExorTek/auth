/**
 * Wrap a user-supplied store into the `IncrStore` interface. Validates
 * that `incr` exists so a misconfiguration surfaces at construction
 * time, not on the first `verifyChallenge({ consume: true })` call.
 * A sync implementation is wrapped transparently — return a plain
 * value or a Promise, either works.
 *
 * Required: `incr(key, ttlMs)`.
 *
 * @param {Partial<import('./index.js').IncrStore>} impl
 * @returns {import('./index.js').IncrStore}
 */
import { isObject, isFunction } from '@exortek/shared/predicates';
import { invalidArgument } from '../internal/guards.js';

export function customStore(impl) {
  if (!isObject(impl) || !isFunction(impl.incr)) {
    throw invalidArgument('customStore(impl) requires an object with an incr(key, ttlMs) method');
  }
  return {
    incr: (key, ttlMs) => Promise.resolve(impl.incr(key, ttlMs)),
  };
}
