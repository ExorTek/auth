/**
 * Family factory for the `customStore(impl)` wrapper every store-shipping
 * package exposes.
 *
 * Each package used to hand-roll the same three steps: assert `impl` is an
 * object, assert its required methods are functions, then `Promise.resolve()`
 * -wrap every call so a sync implementation is transparently promoted to the
 * async store interface. Only the method-name arrays and the typed error
 * differ. This collapses all of that into one binding per package.
 *
 * Consumers: `apikey`, `challenge`, `magic-link`, `opaque`, `session`.
 */

import { isObject, isFunction } from './predicates.js';

/**
 * @param {object} spec
 * @param {readonly string[]} spec.required
 *   Methods that must exist on `impl`; missing ones fail at construction time.
 * @param {readonly string[]} [spec.optional]
 *   Methods wrapped through only when present (feature-gated store extras).
 * @param {(message: string) => Error} spec.wrap
 *   The package's error factory (its `invalidArgument`) — called with a
 *   diagnostic message; its returned typed error is thrown so
 *   `err instanceof <Pkg>Error` holds. A `wrap` that throws directly also
 *   works (the outer `throw` is then unreachable).
 * @param {Record<string, (result: any) => any>} [spec.coerce]
 *   Optional per-method post-processor applied to the resolved result — e.g.
 *   opaque coerces `set` to `undefined` so a native `Map.set` return value
 *   can't leak out as `Promise<Map>`.
 * @returns {(impl: object) => Record<string, (...args: any[]) => Promise<any>>}
 */
export function createCustomStoreValidator({ required, optional = [], wrap, coerce = {} }) {
  return function customStore(impl) {
    if (!isObject(impl)) {
      throw wrap(`customStore(impl) requires an object with { ${required.join(', ')} } methods`);
    }
    for (const name of required) {
      if (!isFunction(impl[name])) {
        throw wrap(`customStore: impl.${name} is required and must be a function`);
      }
    }

    /** @type {Record<string, (...args: any[]) => Promise<any>>} */
    const store = {};
    const bind = name => {
      const post = coerce[name];
      store[name] = post
        ? (...args) => Promise.resolve(impl[name](...args)).then(post)
        : (...args) => Promise.resolve(impl[name](...args));
    };

    for (const name of required) {
      bind(name);
    }
    for (const name of optional) {
      if (isFunction(impl[name])) {
        bind(name);
      }
    }
    return store;
  };
}
