import { CryptoError, ErrorCode } from '../errors.js';

/**
 * @typedef {import('node:crypto').KeyObject} KeyObject
 */

/**
 * @private
 * Module-internal validation helpers used across the crypto package. Each
 * helper throws `CryptoError(INVALID_ARGUMENT)` with a consistent, argument-
 * named message so error surfaces stay uniform.
 *
 * NOT exported from the package public surface — the leading `internal/`
 * segment marks it as implementation detail.
 */

function _fail(name, description) {
  throw new CryptoError(ErrorCode.INVALID_ARGUMENT, `${name} must be ${description}`);
}

/**
 * Assert that `value` is a non-negative safe integer (`0, 1, 2, …`).
 * @param {unknown} value
 * @param {string}  name   Argument name to include in the error message.
 * @returns {void}
 * @throws {CryptoError}
 */
export function assertNonNegativeInt(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) {
    _fail(name, 'a non-negative safe integer');
  }
}

/**
 * Assert that `value` is a strictly positive safe integer (`1, 2, 3, …`).
 * @param {unknown} value
 * @param {string}  name
 */
export function assertPositiveInt(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    _fail(name, 'a positive integer');
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
    _fail(name, 'a non-negative safe integer ≤ 2^48 − 1 (Unix ms since epoch)');
  }
}

/**
 * Assert that `value` is a string (may be empty).
 * @param {unknown} value
 * @param {string}  name
 */
export function assertString(value, name) {
  if (typeof value !== 'string') {
    _fail(name, 'a string');
  }
}

/**
 * Assert that `value` is a plain object (not `null`, not an array, not a primitive).
 * @param {unknown} value
 * @param {string}  name
 */
export function assertObject(value, name) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    _fail(name, 'an object');
  }
}

/**
 * Assert that `value` is either `undefined` or a plain object. Convenience
 * wrapper for the very common "optional options object" pattern.
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
 * Assert that `value` is either a string or a byte buffer (`Buffer` or
 * `Uint8Array`). The `@exortek/crypto` public surface uniformly accepts
 * both representations for opaque data inputs (hash data, hmac secrets,
 * encoder inputs, cipher plaintexts).
 *
 * @param {unknown} value
 * @param {string}  name
 */
export function assertBytesOrString(value, name) {
  if (typeof value !== 'string' && !Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    _fail(name, 'a string or Buffer');
  }
}

/**
 * Assert that `encoding` is one of the accepted output/input encodings.
 * Pass `allowBuffer: false` for cases where a Buffer output makes no sense
 * (verifying a string signature, decoding a token payload).
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
    throw new CryptoError(ErrorCode.INVALID_ARGUMENT, `${name} must be ${list}`);
  }
}

/**
 * Assert that `key` is a Node `KeyObject` of the expected type
 * (`'secret'`, `'public'`, or `'private'`).
 *
 * @param {unknown} key
 * @param {'secret' | 'public' | 'private'} expectedType
 * @param {string}  name
 * @returns {asserts key is KeyObject}
 */
export function assertKeyObject(key, expectedType, name) {
  if (!key || typeof key !== 'object' || key.type !== expectedType) {
    throw new CryptoError(ErrorCode.INVALID_KEY, `${name} must be a ${expectedType} KeyObject`);
  }
}
