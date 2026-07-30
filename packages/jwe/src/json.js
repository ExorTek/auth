/**
 * JWE JSON serialization — General + Flattened (RFC 7516 §3.2 / §7.2).
 *
 * SCAFFOLD: the General form carries one `recipients` array (multi-key
 * enveloping); the Flattened form inlines a single recipient. Both share
 * the same content-encryption step as compact. The implementation lands
 * once the compact encrypt / decrypt core is in place.
 */

import { JweError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {import('./encrypt.js').KeyInput} KeyInput
 * @typedef {import('./encrypt.js').EncryptOptions} EncryptOptions
 * @typedef {import('./decrypt.js').DecryptOptions} DecryptOptions
 * @typedef {import('./decrypt.js').DecryptResult} DecryptResult
 */

/**
 * @typedef {Object} GeneralJwe
 * @property {string} protected  base64url(UTF8(protected header)).
 * @property {Array<{ header?: Record<string, unknown>, encrypted_key: string }>} recipients
 * @property {string} iv
 * @property {string} ciphertext
 * @property {string} tag
 * @property {string} [aad]
 */

/**
 * Encrypt into the General JWE JSON serialization.
 *
 * @param {unknown} _payload
 * @param {Array<{ key: KeyInput, alg: string, kid?: string }>} _recipients
 * @param {Omit<EncryptOptions, 'alg'>} _options
 * @returns {Promise<GeneralJwe>}
 */
export async function encryptJson(_payload, _recipients, _options) {
  throw new JweError(
    ErrorCode.NOT_IMPLEMENTED,
    'jwe.encryptJson is not implemented yet — JSON serialization lands after the compact core.',
  );
}

/**
 * Decrypt a General or Flattened JWE JSON serialization.
 *
 * @param {GeneralJwe | Record<string, unknown>} _jwe
 * @param {KeyInput} _key
 * @param {DecryptOptions} _options
 * @returns {Promise<DecryptResult>}
 */
export async function decryptJson(_jwe, _key, _options) {
  throw new JweError(
    ErrorCode.NOT_IMPLEMENTED,
    'jwe.decryptJson is not implemented yet — JSON serialization lands after the compact core.',
  );
}
