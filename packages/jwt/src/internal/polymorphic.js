/**
 * Polymorphic option helpers — every configurable knob in `@exortek/jwt`
 * accepts either a built-in shortcut or a custom (a)sync function. These
 * helpers centralise the "value or function" pattern so callers stay
 * simple.
 *
 * Scaffold stub; implementations land in the utility-layer commit.
 */

import { JwtError, ErrorCode } from './errors.js';

/**
 * Return `value` if not a function, otherwise call it with `args`.
 * @template T
 * @param {T | ((...a: any[]) => T | Promise<T>)} _value
 * @param {any[]} _args
 * @returns {Promise<T>}
 */
export async function resolveOrCall(_value, ..._args) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'polymorphic.resolveOrCall: not implemented');
}

/**
 * Turn `{ hashAlgo, hashFn }` into a concrete `(plaintext: string) => Promise<string>`.
 * Built-in shortcuts: `'sha256'` (default), `'sha384'`, `'sha512'`.
 *
 * @param {{ hashAlgo?: string, hashFn?: (pt: string) => string | Promise<string> }} [_opts]
 * @returns {(plaintext: string) => Promise<string>}
 */
export function resolveHashFn(_opts) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'polymorphic.resolveHashFn: not implemented');
}

/**
 * Turn an encoding shortcut into a `(bytes: Buffer) => string` encoder.
 * Built-in shortcuts: `'base64url'` (default), `'base64'`, `'hex'`,
 * `'crockford'`, `'uuid'`.
 *
 * @param {string} [_encoding]
 * @returns {(bytes: Buffer) => string}
 */
export function resolveEncoding(_encoding) {
  throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'polymorphic.resolveEncoding: not implemented');
}
