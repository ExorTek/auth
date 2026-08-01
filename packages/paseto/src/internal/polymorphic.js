/**
 * Polymorphic option helpers for the token-pair layer — every knob
 * accepts a built-in shortcut or a custom (a)sync function. Mirrors the
 * convention used across `@exortek/*`: omit → default, string/object →
 * built-in, `async fn` → caller's logic wins.
 */

import { createHash, randomUUID } from 'node:crypto';

import { resolveOrCall, randomBuffer } from '@exortek/shared/resolve';
import { encode as crockfordEncode } from '@exortek/shared/crockford';
import { isFunction } from '@exortek/shared/predicates';

import { PasetoError, ErrorCode } from './errors.js';

export { resolveOrCall, randomBuffer };

const HASH_ALGO_BUILTIN = new Set(['sha256', 'sha384', 'sha512']);

/**
 * Resolve `{ hashAlgo, hashFn }` into a `(pt: string) => Promise<string>`
 * used to derive a refresh token's storage key. Custom `hashFn` wins;
 * default is `sha256` hex.
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
    throw new PasetoError(
      ErrorCode.INVALID_ARGUMENT,
      `resolveHashFn: unknown hashAlgo ${JSON.stringify(algo)}. Built-in: ${[...HASH_ALGO_BUILTIN].join(', ')}. Pass a custom hashFn for anything else.`,
    );
  }
  return async plaintext => createHash(algo).update(plaintext).digest('hex');
}

/**
 * Resolve an encoding shortcut into a `(bytes: Buffer) => string` encoder.
 * Built-ins: `base64url` (default), `base64`, `hex`, `crockford`, `uuid`.
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
      throw new PasetoError(
        ErrorCode.INVALID_ARGUMENT,
        `resolveEncoding: unknown encoding ${JSON.stringify(encoding)}. Built-in: base64url | base64 | hex | crockford | uuid.`,
      );
  }
}
