import { CryptoError, ErrorCode } from '../errors.js';

/**
 * @typedef {import('node:crypto').KeyObject} KeyObject
 */

/**
 * Human-readable hint about what a caller passed instead of a
 * `KeyObject`. Called on the failure path only — the goal is to save
 * the reader a debug session when the shape looks like a common
 * mistake.
 *
 * @private
 * @param {unknown} key
 * @returns {string}
 */
function _describeKeyProblem(key) {
  if (key === null || key === undefined) {
    return `got ${key}`;
  }
  if (typeof key === 'string') {
    return `got a string — wrap raw bytes with crypto.createSecretKey(Buffer.from(...)), or use cipher.encryptWithPassphrase for passphrase-based encryption`;
  }
  if (typeof key === 'object' && typeof key.then === 'function') {
    return `got a Promise — did you forget "await"? e.g. const key = await cipher.generateKey()`;
  }
  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    return `got raw bytes — wrap with crypto.createSecretKey(buf) first, or use cipher.encryptWithPassphrase`;
  }
  if (typeof key === 'object' && typeof key.type !== 'string') {
    return `got ${key.constructor?.name ?? 'an object'} without a .type field — generate one via await cipher.generateKey() or await cipher.generateKeyPair(...)`;
  }
  return `got a ${typeof key}`;
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
  if (key && typeof key === 'object' && typeof key.type === 'string' && key.type !== expectedType) {
    throw new CryptoError(
      ErrorCode.INVALID_KEY,
      `${name} must be a ${expectedType} KeyObject; got a ${key.type} KeyObject`,
    );
  }
  if (!key || typeof key !== 'object' || key.type !== expectedType) {
    throw new CryptoError(
      ErrorCode.INVALID_KEY,
      `${name} must be a ${expectedType} KeyObject; ${_describeKeyProblem(key)}`,
    );
  }
}

/**
 * @private — same actionable-message helper for callers that need to
 * run their own key-type dispatch (the polymorphic `cipher.encrypt` /
 * `cipher.decrypt`, which accept multiple `KeyObject` types).
 */
export function _keyProblemHint(key) {
  return _describeKeyProblem(key);
}
