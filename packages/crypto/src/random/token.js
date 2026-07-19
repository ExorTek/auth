import { CryptoError, ErrorCode } from '../errors.js';
import { assertNonNegativeInt, assertObject, assertString } from '../internal/guards.js';
import { base64url } from './base64url.js';
import { base64 } from './base64.js';
import { hex } from './hex.js';
import { crockford } from './crockford.js';
import { base58 } from './base58.js';

/** Registry of built-in encoders. Adding one here surfaces it via `options.encoding`. */
const ENCODERS = Object.freeze({
  base64url,
  base64,
  hex,
  crockford,
  base58,
});

/** Public list of encoding names — useful for algorithm-picker UIs or validation. */
export const TOKEN_ENCODINGS = /** @type {readonly (keyof typeof ENCODERS)[]} */ (Object.freeze(Object.keys(ENCODERS)));

/**
 * @typedef {'base64url' | 'base64' | 'hex' | 'crockford' | 'base58'} TokenEncoding
 */

/**
 * @typedef {object} TokenOptions
 * @property {string}         [prefix]     Optional identifier prefix (e.g. `'usr'`, `'sk_live'`).
 *                                          When provided, output is `<prefix><separator><body>`.
 * @property {string}         [separator]  Character(s) between prefix and body. Defaults to `'_'`
 *                                          (Stripe-style). Empty string is rejected — use no prefix
 *                                          instead. Ignored when `prefix` is not set.
 * @property {TokenEncoding}  [encoding]   Output alphabet for the random body:
 *                                          - `'base64url'` (default) — URL-safe, no padding
 *                                          - `'base64'` — standard, padded
 *                                          - `'hex'` — lowercase
 *                                          - `'crockford'` — sortable, look-alike free
 *                                          - `'base58'` — Bitcoin-style, look-alike free
 */

/**
 * Prefixed random token (Stripe-style).
 *
 * Returns `<prefix><separator><body>` when `options.prefix` is set,
 * otherwise a bare random body. The body is generated from `size` random
 * bytes of entropy, encoded with the alphabet selected by `options.encoding`.
 *
 * Sensible defaults for common use cases:
 * - **API keys / long-lived tokens**: `size: 32` (256 bits) — 43-char base64url body
 * - **Session / verification tokens**: `size: 16` (128 bits) — 22-char base64url body
 * - **Short shareable IDs**: `size: 8`, `encoding: 'crockford'` — 13-char sortable string
 *
 * @param {number}       size       Random bytes for the token body. Non-negative integer.
 * @param {TokenOptions} [options]
 * @returns {string}                Prefixed or bare token.
 * @throws {CryptoError}            With code `INVALID_ARGUMENT` if `size` is invalid,
 *                                  `options` is not an object, `prefix` / `separator` are
 *                                  provided but not strings, `separator` is an empty string,
 *                                  or `encoding` is not one of {@link TOKEN_ENCODINGS}.
 *
 * @example
 * token(32)                                             // 'V1StGXR8_Z5jdHi6...' (base64url)
 * token(32, { prefix: 'usr' })                          // 'usr_V1StGXR8_Z5jdHi6...'
 * token(32, { prefix: 'sk_live', separator: '-' })      // 'sk_live-V1StGXR8...'
 * token(16, { encoding: 'crockford' })                  // 'V1StGXR8Z5jdHi6B'  (sortable)
 * token(16, { encoding: 'base58', prefix: 'wallet' })   // 'wallet_...'         (look-alike free)
 */
export function token(size, options) {
  assertNonNegativeInt(size, 'size');
  if (options !== undefined) {
    assertObject(options, 'options');
    if (options.prefix !== undefined) {
      assertString(options.prefix, 'options.prefix');
    }
    if (options.separator !== undefined) {
      assertString(options.separator, 'options.separator');
      if (options.separator === '') {
        throw new CryptoError(
          ErrorCode.INVALID_ARGUMENT,
          "options.separator must be a non-empty string; got ''. Omit the option to use the default '_', or pass a single character like '-'.",
        );
      }
    }
    if (options.encoding !== undefined && !(options.encoding in ENCODERS)) {
      throw new CryptoError(
        ErrorCode.INVALID_ARGUMENT,
        `options.encoding must be one of: ${TOKEN_ENCODINGS.join(', ')}`,
      );
    }
  }

  const encoder = ENCODERS[options?.encoding ?? 'base64url'];
  const body = encoder(size);

  const prefix = options?.prefix;
  if (!prefix) {
    return body;
  }
  const separator = options.separator ?? '_';
  return `${prefix}${separator}${body}`;
}
