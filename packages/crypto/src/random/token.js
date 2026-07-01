import { assertObject, assertString } from '../internal/validate.js';
import { base64url } from './base64url.js';

/**
 * @typedef {object} TokenOptions
 * @property {string} [prefix]     Optional identifier prefix (e.g. `'usr'`, `'sk_live'`).
 *                                 When provided, output is `<prefix><separator><body>`.
 * @property {string} [separator]  Character(s) between prefix and body. Defaults to `'_'`
 *                                 (Stripe-style). Ignored when `prefix` is not set.
 */

/**
 * Prefixed URL-safe random token (Stripe-style).
 *
 * Returns `<prefix><separator><base64url(size)>` when `options.prefix` is set,
 * otherwise a bare base64url body. The random body is generated with
 * {@link base64url} (URL-safe, no `=` padding).
 *
 * Recommended sizes: **16 bytes** (128 bits, 22 chars) for opaque session /
 * verification tokens, **32 bytes** (256 bits, 43 chars) for long-lived API
 * keys and refresh tokens.
 *
 * @param {number}       size       Random bytes for the token body. Non-negative integer.
 * @param {TokenOptions} [options]
 * @returns {string}                Prefixed or bare token.
 * @throws {CryptoError}            With code `INVALID_ARGUMENT` if `size` is invalid
 *                                  (from {@link bytes}), or `prefix` / `separator`
 *                                  are provided but not strings.
 *
 * @example
 * token(32)                                            // 'V1StGXR8_Z5jdHi6...'
 * token(32, { prefix: 'usr' })                         // 'usr_V1StGXR8_Z5jdHi6...'
 * token(32, { prefix: 'sk_live', separator: '-' })     // 'sk_live-V1StGXR8_Z5jdHi6...'
 */
export function token(size, options) {
  if (options !== undefined) {
    assertObject(options, 'options');
    if (options.prefix !== undefined) {
      assertString(options.prefix, 'options.prefix');
    }
    if (options.separator !== undefined) {
      assertString(options.separator, 'options.separator');
    }
  }

  const body = base64url(size);
  const prefix = options?.prefix;
  if (!prefix) {
    return body;
  }
  const separator = options.separator ?? '_';
  return `${prefix}${separator}${body}`;
}
