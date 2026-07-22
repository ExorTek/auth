/**
 * Non-throwing type predicates. Companion to `asserts.js`.
 *
 * ### When to reach for which
 *
 * - Writing a **throw-guard** at a function boundary — a bad shape
 *   should fail with the caller's typed error class? Use
 *   `asserts` + `defineGuards` (`assertObject`, `assertString`, …).
 *   The `assert*` family bundles the check with the correctly-bound
 *   throw and preserves the "one error class per package" contract.
 *
 * - Writing a **dispatch / branch / fallback** where the wrong shape
 *   is meant to be handled, not thrown? Use these predicates.
 *   Typical shapes:
 *
 *     if (isObject(config.store)) { ... } else { ... }
 *
 *     const isManager = isObject(v) && isFunction(v.issue);
 *
 * The two APIs deliberately do not overlap in intent: `assert*` throws,
 * `is*` never does. Bypassing an `assert*` with an `if (!is*(x)) throw
 * new PkgError(...)` pattern skips the package's guards binding and
 * duplicates work the assert family already handles — don't.
 */

/**
 * `true` when `value` is a plain object *or* a class instance — anything
 * whose property access is safe. Rejects `null`, arrays, and every
 * primitive.
 *
 * The Node convention `typeof x === 'object' && x !== null` accepts
 * arrays, which almost never matches caller intent (an array is not a
 * "config object"). This predicate additionally rules arrays out, so
 * `isObject(x)` really means "I can read `x.foo` without exploding on
 * a numeric index".
 *
 * Class instances (Node `KeyObject`, `URL`, user-defined classes) pass
 * because they carry `typeof === 'object'` — the check is duck-typed,
 * not prototype-restricted.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * `true` when `value` is a string primitive. `String` boxed objects
 * (from `new String('x')`) are refused — those are a footgun almost no
 * one wants, and every place in this codebase reads strings by
 * primitive access.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isString(value) {
  return typeof value === 'string';
}

/**
 * `true` when `value` is a non-empty string primitive — string with
 * `length > 0`. Short-circuits the common `isString(x) && x.length > 0`
 * pattern at branch sites.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

/**
 * `true` when `value` is a function. Class constructors, arrow
 * functions, and generator functions all pass — `typeof` on any
 * callable is `'function'`.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isFunction(value) {
  return typeof value === 'function';
}

/**
 * `true` when `value` is a `Buffer` or a `Uint8Array` — the two byte
 * shapes every crypto surface in this repo accepts interchangeably.
 * Rejects strings so dispatch code can decide whether a string input
 * means "already-encoded bytes" (decode it) or "wrong type" (branch).
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isBytes(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array;
}
