/**
 * Polymorphic option helpers — every configurable knob in `@exortek/jwt`
 * accepts either a built-in shortcut or a custom (a)sync function.
 * These helpers centralise the "value or function" pattern so the
 * calling code stays boring.
 *
 * Three-tier API convention:
 *
 *   1. Omit → industry default
 *   2. Built-in string / object → dispatched here to a concrete impl
 *   3. `async fn` → user's own logic wins
 */

import { createHash, randomUUID } from 'node:crypto';

import { resolveOrCall, randomBuffer } from '@exortek/shared/resolve';
import { encode as crockfordEncode } from '@exortek/shared/crockford';
import { isFunction } from '@exortek/shared/predicates';

import { JwtError, ErrorCode } from './errors.js';

export { resolveOrCall, randomBuffer };

/** Supported built-in hash algorithms for the JWT store-key derivation. */
const HASH_ALGO_BUILTIN = new Set(['sha256', 'sha384', 'sha512']);

/**
 * Turn `{ hashAlgo, hashFn }` into a concrete
 * `(plaintext: string) => Promise<string>`. Custom `hashFn` wins over
 * the built-in `hashAlgo` shortcut.
 *
 * Default: `sha256` + hex output.
 *
 * @param {{ hashAlgo?: string, hashFn?: (pt: string) => string | Promise<string> }} [opts]
 * @returns {(plaintext: string) => Promise<string>}
 */
export function resolveHashFn(opts) {
  const cfg = opts || {};
  if (isFunction(cfg.hashFn)) {
    const fn = cfg.hashFn;
    return async plaintext => fn(plaintext);
  }
  const algo = cfg.hashAlgo || 'sha256';
  if (!HASH_ALGO_BUILTIN.has(algo)) {
    throw new JwtError(
      ErrorCode.INVALID_ARGUMENT,
      `resolveHashFn: unknown hashAlgo ${JSON.stringify(algo)}. Built-in: ${[...HASH_ALGO_BUILTIN].join(', ')}. Pass a custom hashFn for anything else.`,
    );
  }
  return async plaintext => createHash(algo).update(plaintext).digest('hex');
}

/**
 * Turn an encoding shortcut into a `(bytes: Buffer) => string` encoder.
 *
 * Built-in shortcuts: `'base64url'` (default), `'base64'`, `'hex'`,
 * `'crockford'` (Crockford Base32, RFC 4648-ish with I/L/O/U dropped),
 * `'uuid'` (returns a v4 UUID string; ignores input bytes).
 *
 * @param {string} [encoding]
 * @returns {(bytes: Buffer) => string}
 */
export function resolveEncoding(encoding) {
  const enc = (encoding || 'base64url').toLowerCase();
  switch (enc) {
    case 'base64url':
      return bytes => bytes.toString('base64url');
    case 'base64':
      return bytes => bytes.toString('base64');
    case 'hex':
      return bytes => bytes.toString('hex');
    case 'crockford':
      return crockfordEncode;
    case 'uuid':
      return () => randomUUID();
    default:
      throw new JwtError(
        ErrorCode.INVALID_ARGUMENT,
        `resolveEncoding: unknown encoding ${JSON.stringify(encoding)}. Built-in: base64url | base64 | hex | crockford | uuid.`,
      );
  }
}
