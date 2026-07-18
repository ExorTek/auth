/**
 * Imperative single-argument guard helpers — the everyday
 * `assertPositiveInt(x, 'options.iterations')` shape used at API
 * boundaries. Companion to the compound schema builder in
 * `@exortek/shared/validate`:
 *
 *   - **schema** for whole options objects (`object({...})`, `parse`).
 *   - **asserts** for one-liner argument guards at the call site.
 *
 * Failures throw a plain `Error` **carrying `err.code =
 * 'INVALID_ARGUMENT'`** — the machine-readable code every
 * `@exortek/*` package's typed errors already expose. Consumers
 * import and use directly; there is no per-package wrapping
 * ceremony:
 *
 *   import { assertPositiveInt } from '@exortek/shared/asserts';
 *   assertPositiveInt(options.iterations, 'options.iterations');
 *
 * Callers that need to branch on the failure branch on
 * `err.code === 'INVALID_ARGUMENT'`, same as they do for the typed
 * classes. `instanceof CryptoError` (or the like) does NOT match —
 * that's the deliberate trade for the "one-line callsite, no wrap"
 * ergonomics.
 */

function fail(name, description) {
  const err = new Error(`${name} must be ${description}`);
  // Machine-readable marker so consumers branch on `err.code` even
  // though the class is a plain `Error` — the same convention every
  // `@exortek/*` package's typed errors already use.
  err.code = 'INVALID_ARGUMENT';
  throw err;
}

/**
 * Assert that `value` is a non-negative safe integer (`0, 1, 2, …`).
 * @param {unknown} value
 * @param {string}  name  Argument name to include in the error message.
 */
export function assertNonNegativeInt(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(name, 'a non-negative safe integer');
  }
}

/**
 * Assert that `value` is a strictly positive safe integer (`1, 2, 3, …`).
 * @param {unknown} value
 * @param {string}  name
 */
export function assertPositiveInt(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(name, 'a positive integer');
  }
}

/**
 * Assert that `value` fits in a 48-bit unsigned integer (`0 … 2^48 − 1`).
 * Used for Unix millisecond timestamps in UUID v7 / ULID.
 * @param {unknown} value
 * @param {string}  name
 */
export function assertUint48(value, name) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffffffff) {
    fail(name, 'a non-negative safe integer ≤ 2^48 − 1 (Unix ms since epoch)');
  }
}

/**
 * Assert that `value` is a string (may be empty).
 * @param {unknown} value
 * @param {string}  name
 */
export function assertString(value, name) {
  if (typeof value !== 'string') {
    fail(name, 'a string');
  }
}

/**
 * Assert that `value` is a plain object (not `null`, not an array,
 * not a primitive).
 * @param {unknown} value
 * @param {string}  name
 */
export function assertObject(value, name) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail(name, 'an object');
  }
}

/**
 * Assert that `value` is either `undefined` or a plain object.
 * Convenience wrapper for the very common "optional options object"
 * pattern.
 * @param {unknown} value
 * @param {string}  name
 */
export function assertOptionalObject(value, name) {
  if (value === undefined) {
    return;
  }
  assertObject(value, name);
}

/**
 * Assert that `value` is either a string or a byte buffer (`Buffer`
 * or `Uint8Array`).
 * @param {unknown} value
 * @param {string}  name
 */
export function assertBytesOrString(value, name) {
  if (typeof value !== 'string' && !Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    fail(name, 'a string or Buffer');
  }
}

/**
 * Assert that `encoding` is one of the accepted output/input encodings.
 * Pass `allowBuffer: false` for cases where a `Buffer` output makes no
 * sense (verifying a string signature, decoding a token payload).
 *
 * @param {unknown} encoding
 * @param {string}  name
 * @param {{ allowBuffer?: boolean }} [options]
 */
export function assertEncoding(encoding, name, options) {
  const allowBuffer = options?.allowBuffer !== false;
  const valid =
    encoding === 'hex' || encoding === 'base64' || encoding === 'base64url' || (allowBuffer && encoding === 'buffer');
  if (!valid) {
    const list = allowBuffer ? "'hex', 'base64', 'base64url', or 'buffer'" : "'hex', 'base64', or 'base64url'";
    fail(name, list);
  }
}
