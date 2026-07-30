/**
 * Compact JWE production — `encrypt(payload, key, options)` (RFC 7516 §3.1).
 *
 * SCAFFOLD: the signature and options contract are frozen here so the
 * public surface and types are stable; the encryption core (CEK
 * generation, `alg` key-management wrap, `enc` AEAD, 5-segment assembly)
 * lands in the next implementation commit.
 */

import { JweError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {import('node:crypto').KeyObject | Buffer | Uint8Array | Record<string, unknown>} KeyInput
 */

/**
 * @typedef {Object} EncryptOptions
 * @property {string} alg  Key-management algorithm (REQUIRED) — e.g.
 *   `'RSA-OAEP-256'`, `'ECDH-ES+A256KW'`, `'A256KW'`, `'dir'`.
 * @property {string} enc  Content-encryption algorithm (REQUIRED) — e.g.
 *   `'A256GCM'`, `'A128CBC-HS256'`.
 * @property {string} [kid]  Key ID written to the protected header.
 * @property {Record<string, unknown>} [header]  Extra protected-header
 *   params, merged after `alg` / `enc` / `kid` (those are never overridden).
 * @property {string | number} [expiresIn]  When the payload is a JSON
 *   object, stamp an `exp` claim this far in the future.
 */

/**
 * Encrypt a payload into a compact JWE string.
 *
 * @param {unknown} _payload
 * @param {KeyInput} _key
 * @param {EncryptOptions} _options
 * @returns {Promise<string>}
 */
export async function encrypt(_payload, _key, _options) {
  throw new JweError(
    ErrorCode.NOT_IMPLEMENTED,
    'jwe.encrypt is not implemented yet — the encryption core lands in a follow-up commit.',
  );
}
