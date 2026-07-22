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

/**
 * `true` when `value` is a number primitive. Rejects `NaN`, which is
 * technically a number but almost never what the caller intends.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isNumber(value) {
  return typeof value === 'number' && !Number.isNaN(value);
}

/**
 * `true` when `value` is a boolean primitive.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isBoolean(value) {
  return typeof value === 'boolean';
}

/**
 * `true` when `value` is `undefined`.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isUndefined(value) {
  return typeof value === 'undefined';
}

/**
 * `true` when `value` is a `bigint` primitive. Rejects the boxed form
 * `Object(1n)` because boxed primitives are a footgun almost never used
 * in server-side code.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isBigInt(value) {
  return typeof value === 'bigint';
}

/**
 * `true` when `value` is a `symbol`. Every `Symbol()` and
 * `Symbol.for('x')` returns a primitive symbol; boxed symbols are not
 * accepted.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isSymbol(value) {
  return typeof value === 'symbol';
}

/**
 * `true` for literal `null`. Prefer `!isNullish(x)` over `!isNull(x)`
 * when the caller might pass `undefined` — see {@link isNullish}.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isNull(value) {
  return value === null;
}

/**
 * `true` for `null` OR `undefined`. Standard "empty slot" check that
 * mirrors the nullish-coalescing (`??`) operator.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isNullish(value) {
  return value === null || value === undefined;
}

/**
 * `true` for arrays. Thin wrapper over `Array.isArray` so predicates
 * live under one import; identical behaviour.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isArray(value) {
  return Array.isArray(value);
}

/**
 * `true` when `value` is a Node.js `Buffer`. Uint8Array-only shapes are
 * refused — use {@link isBytes} when either satisfies the contract.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isBuffer(value) {
  return Buffer.isBuffer(value);
}

/**
 * `true` when `value` is a `Uint8Array` (including `Buffer`, which
 * extends `Uint8Array`). Distinguishes from other `TypedArray` shapes
 * — `Uint16Array` and friends fail.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isUint8Array(value) {
  return value instanceof Uint8Array;
}

/**
 * `true` for the literal `true`. Sugar for `x === true`; unlike a bare
 * `if (x)`, does not match truthy strings, non-zero numbers, or
 * objects.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isTrue(value) {
  return value === true;
}

/**
 * `true` for the literal `false`. Sugar for `x === false`; unlike a
 * bare `if (!x)`, does not match `0`, `''`, `null`, or `undefined`.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isFalse(value) {
  return value === false;
}

/**
 * `true` for a finite `number` — `NaN`, `Infinity`, and `-Infinity` all
 * fail. Use when the caller needs a number they can compute with;
 * mirrors `Number.isFinite` semantics under a predicate-style name.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

/**
 * `true` for a safe integer — a finite `number` inside `[MIN_SAFE_INTEGER,
 * MAX_SAFE_INTEGER]` with no fractional part. Mirrors `Number.isSafeInteger`.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isInteger(value) {
  return Number.isSafeInteger(value);
}
