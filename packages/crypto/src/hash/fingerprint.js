import { isArray, isBigInt, isBoolean, isBytes, isFunction, isString, isSymbol, isUndefined } from '@exortek/shared/predicates';

import { invalidArgument } from '../internal/guards.js';
import { hash } from './hash.js';

/**
 * @typedef {import('./hash.js').HashOptions} HashOptions
 */

/**
 * Deterministic content-addressed hash of an arbitrary JSON-shaped value.
 *
 * `JSON.stringify` doesn't guarantee key order, so two equivalent objects
 * can hash differently. `fingerprint` first canonicalises the input — object
 * keys are sorted lexicographically (UTF-16 code-unit order, per RFC 8785),
 * whitespace stripped, `Date` and `.toJSON()`-bearing objects unwrapped — and
 * then hashes the resulting bytes. Same input, same bytes, same digest, on
 * every runtime and every Node version.
 *
 * Ideal for:
 *   - Cache / ETag keys derived from a request body or query object.
 *   - Idempotency keys for at-least-once APIs.
 *   - Deduplication IDs for event streams (compute once at the producer).
 *
 * Accepted values: `null`, `boolean`, finite `number`, `string`, `Array`,
 * plain object, or any value with a `toJSON()` method.
 *
 * Rejected values: `undefined`, `bigint`, `symbol`, function, `NaN`,
 * `±Infinity`, `Buffer` / `Uint8Array` (base64-encode first), and any
 * object with a cyclic reference.
 *
 * @param {unknown}     value
 * @param {HashOptions} [options]
 * @returns {string | Buffer}
 * @throws {CryptoError} `INVALID_ARGUMENT` for unsupported types or cycles,
 *                       `UNSUPPORTED_ALGORITHM` for a bad `options.algo`.
 *
 * @example
 * fingerprint({ b: 2, a: 1 }) === fingerprint({ a: 1, b: 2 })  // true
 * fingerprint({ items: [{ id: 2 }, { id: 1 }] })              // stable across
 *                                                              // Node versions
 * fingerprint(payload, { algo: 'sha512', encoding: 'base64url' })
 */
export function fingerprint(value, options) {
  const canonical = _canonicalize(value, new WeakSet(), 'value');
  return hash(canonical, options);
}

/**
 * @private
 * @param {unknown}  value
 * @param {WeakSet<object>} seen
 * @param {string}   path      Dotted path from root — surfaced in error messages
 *                             so callers can pinpoint the offending field.
 * @returns {string}
 */
function _canonicalize(value, seen, path) {
  if (value === null) {
    return 'null';
  }
  if (isBoolean(value)) {
    return value ? 'true' : 'false';
  }
  // `typeof x === 'number'` — not the `isNumber` predicate, which rejects
  // NaN. We want NaN and Infinity to enter this branch so we can throw a
  // specific "not hashable" error instead of falling through to WeakSet
  // (which crashes on NaN with "Invalid value used in weak set").
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw invalidArgument(`${path} is a non-finite number (NaN / Infinity); not hashable`);
    }
    // JSON.stringify emits ECMAScript ToString for numbers, matching RFC 8785.
    return JSON.stringify(value);
  }
  if (isString(value)) {
    return JSON.stringify(value);
  }
  if (isBigInt(value)) {
    throw invalidArgument(`${path} is a bigint; JSON has no bigint representation. Convert to string first.`);
  }
  if (isSymbol(value) || isFunction(value) || isUndefined(value)) {
    throw invalidArgument(`${path} is a ${typeof value}; not hashable`);
  }
  // From here: object-like.
  if (seen.has(value)) {
    throw invalidArgument(`${path} contains a cyclic reference`);
  }
  seen.add(value);
  // Reject bytes before .toJSON — Buffer's .toJSON returns `{ type, data: [...] }`
  // which would silently produce a stable but surprising fingerprint.
  if (isBytes(value)) {
    throw invalidArgument(`${path} is a Buffer/Uint8Array; encode as base64/hex first for a stable fingerprint`);
  }
  if (isFunction(value.toJSON)) {
    return _canonicalize(value.toJSON(path), seen, path);
  }
  if (isArray(value)) {
    let out = '[';
    for (let i = 0; i < value.length; i++) {
      if (i > 0) {
        out += ',';
      }
      out += _canonicalize(value[i], seen, `${path}[${i}]`);
    }
    return out + ']';
  }
  // Plain object — sort keys by UTF-16 code unit order (RFC 8785 §3.2.3).
  const keys = Object.keys(value).sort();
  let out = '{';
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i];
    if (i > 0) {
      out += ',';
    }
    out += JSON.stringify(k) + ':' + _canonicalize(value[k], seen, `${path}.${k}`);
  }
  return out + '}';
}
