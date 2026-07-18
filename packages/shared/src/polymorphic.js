/**
 * Small helpers for the "value | shortcut string | async function"
 * escape hatch that every configurable knob in this stack exposes:
 * every option accepts either a direct value, a well-known preset
 * string, or a caller-supplied function.
 */

import { createHash, randomUUID } from 'node:crypto';

import { randomBuffer } from './crypto/random.js';

/**
 * Call `value` with the given args if it's a function, otherwise
 * return it as-is. Async-safe.
 *
 * @template T
 * @template {readonly unknown[]} A
 * @param {T | ((...args: A) => T | Promise<T>)} value
 * @param {A} args
 * @returns {Promise<T>}
 */
export async function resolveOrCall(value, ...args) {
  if (typeof value === 'function') {
    return await /** @type {(...a: A) => T | Promise<T>} */ (value)(...args);
  }
  return value;
}

/**
 * Resolve a hash-function shortcut into an actual `(input) => digest`.
 *
 * Accepts:
 *   - A function → returned as-is.
 *   - A string preset (`'sha256'`, `'sha384'`, `'sha512'`) → returns a
 *     function that hashes the input with that algorithm and returns
 *     the hex digest.
 *   - `undefined` → defaults to `'sha256'`.
 *
 * @param {string | ((input: string) => string | Promise<string>) | undefined} spec
 * @returns {(input: string) => string | Promise<string>}
 */
export function resolveHashFn(spec) {
  if (typeof spec === 'function') {
    return spec;
  }
  const algo = spec || 'sha256';
  return input => createHash(algo).update(input).digest('hex');
}

/**
 * Resolve an encoding shortcut into an actual `(bytes) => string`.
 *
 * Accepts:
 *   - A function → returned as-is.
 *   - A string preset (`'base64url'`, `'base64'`, `'hex'`, `'uuid'`).
 *   - `undefined` → defaults to `'base64url'`.
 *
 * `'uuid'` is a special preset that ignores the input bytes and emits
 * a fresh v4 UUID; useful for opaque token minting where the caller
 * wants human-friendly identifiers instead of raw bytes.
 *
 * @param {string | ((bytes: Buffer) => string) | undefined} spec
 * @returns {(bytes: Buffer) => string}
 */
export function resolveEncoding(spec) {
  if (typeof spec === 'function') {
    return spec;
  }
  const enc = spec || 'base64url';
  switch (enc) {
    case 'base64url':
      return bytes => bytes.toString('base64url');
    case 'base64':
      return bytes => bytes.toString('base64');
    case 'hex':
      return bytes => bytes.toString('hex');
    case 'uuid':
      return () => randomUUID();
    default:
      throw new Error(`resolveEncoding: unknown encoding ${JSON.stringify(enc)}`);
  }
}

export { randomBuffer };
