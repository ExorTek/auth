import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertBytesOrString, assertObject, assertString } from '@exortek/shared/asserts';

import { assertKeyObject } from '../internal/validate.js';
import { toBuffer } from '../internal/bytes.js';
import { SYMMETRIC, SYMMETRIC_ALGOS } from './algorithms.js';

/**
 * @typedef {import('node:crypto').KeyObject} KeyObject
 * @typedef {import('./algorithms.js').SymmetricAlgorithm} SymmetricAlgorithm
 */

/**
 * @typedef {object} EncryptResult
 * @property {Buffer} ciphertext
 * @property {Buffer} iv
 * @property {Buffer} tag  Empty buffer for non-AEAD modes (aes-256-cbc).
 */

/**
 * @typedef {object} SymmetricOptions
 * @property {SymmetricAlgorithm} [algo='aes-256-gcm']
 * @property {string | Buffer | Uint8Array} [aad]  Additional authenticated data (AEAD modes only).
 */

/**
 * Encrypt `data` with a symmetric key.
 *
 * Generates a fresh random IV per call, so encrypting the same plaintext
 * twice produces different ciphertexts (semantic security). For AEAD
 * modes (`aes-256-gcm`, `chacha20-poly1305`) the authentication tag is
 * returned alongside the ciphertext and must be supplied to
 * {@link decryptSymmetric}.
 *
 * Bind the ciphertext to non-secret context (user id, transaction id,
 * request id, …) by passing `options.aad`; anyone flipping that context
 * during transit will make decryption fail.
 *
 * @param {string | Buffer | Uint8Array} data
 * @param {KeyObject}         key
 * @param {SymmetricOptions}  [options]
 * @returns {EncryptResult}
 * @throws {CryptoError}   With code `INVALID_ARGUMENT` for bad inputs,
 *                         `INVALID_KEY` for non-secret keys, or
 *                         `UNSUPPORTED_ALGORITHM` for unknown `options.algo`.
 *
 * @example
 * const key = await generateKey()
 * const { ciphertext, iv, tag } = encryptSymmetric('hello', key)
 *
 * @example
 * // AAD binds ciphertext to context — tag verifies both together.
 * encryptSymmetric(payload, key, { aad: `user:${userId}` })
 */
export function encryptSymmetric(data, key, options) {
  assertBytesOrString(data, 'data');
  assertKeyObject(key, 'secret', 'symmetric key');
  const spec = _resolveSymmetric(options);
  if (options?.aad !== undefined) {
    assertBytesOrString(options.aad, 'options.aad');
  }

  const iv = crypto.randomBytes(spec.spec.ivLength);
  const cipher = crypto.createCipheriv(spec.algo, key, iv);
  if (options?.aad !== undefined && spec.spec.mode === 'aead') {
    cipher.setAAD(toBuffer(options.aad, 'options.aad'));
  }

  const ciphertext = Buffer.concat([cipher.update(toBuffer(data, 'data')), cipher.final()]);
  const tag = spec.spec.mode === 'aead' ? cipher.getAuthTag() : Buffer.alloc(0);

  return { ciphertext, iv, tag };
}

/**
 * @typedef {object} DecryptOptions
 * @property {SymmetricAlgorithm}          [algo='aes-256-gcm']
 * @property {Buffer | Uint8Array}          iv
 * @property {Buffer | Uint8Array}          [tag]  Required for AEAD modes.
 * @property {string | Buffer | Uint8Array} [aad]  Must match the AAD used during encryption.
 */

/**
 * Decrypt a symmetric ciphertext.
 *
 * For AEAD modes (`aes-256-gcm`, `chacha20-poly1305`), integrity is checked
 * BEFORE any plaintext is produced — a bad tag, tampered ciphertext, wrong
 * key or altered AAD all raise `CryptoError(DECRYPT_FAILED)` with no side
 * channel leak.
 *
 * @param {Buffer | Uint8Array} ciphertext
 * @param {KeyObject}           key
 * @param {DecryptOptions}      options   `iv` (and `tag` for AEAD) are mandatory.
 * @returns {Buffer}                       Plaintext bytes.
 * @throws {CryptoError}   With code:
 *   - `INVALID_ARGUMENT` if `ciphertext`, `iv` or (AEAD) `tag` are missing / wrong type
 *   - `INVALID_KEY` if `key` is not a secret KeyObject
 *   - `UNSUPPORTED_ALGORITHM` for unknown `options.algo`
 *   - `DECRYPT_FAILED` on any authentication failure
 *
 * @example
 * const plaintext = decryptSymmetric(ciphertext, key, { iv, tag })
 *
 * @example
 * // AAD verification — same AAD as encryption or the tag check fails:
 * decryptSymmetric(ct, key, { iv, tag, aad: `user:${userId}` })
 */
export function decryptSymmetric(ciphertext, key, options) {
  if (!(ciphertext instanceof Uint8Array)) {
    throw new CryptoError(
      ErrorCode.INVALID_ARGUMENT,
      'ciphertext must be a Buffer or Uint8Array — the raw bytes produced by encryptSymmetric().ciphertext. For a base64url string, use decryptFromString() instead.',
    );
  }
  assertKeyObject(key, 'secret', 'symmetric key');
  assertObject(options, 'options');
  const spec = _resolveSymmetric(options);
  if (!(options.iv instanceof Uint8Array)) {
    throw new CryptoError(
      ErrorCode.INVALID_ARGUMENT,
      `options.iv is required and must be a Buffer — pass the iv returned from encryptSymmetric() (${spec.spec.ivLength} bytes for ${spec.algo})`,
    );
  }
  if (spec.spec.mode === 'aead' && !(options.tag instanceof Uint8Array)) {
    throw new CryptoError(
      ErrorCode.INVALID_ARGUMENT,
      `options.tag is required for AEAD mode ${spec.algo} — pass the tag returned from encryptSymmetric() (${spec.spec.tagLength} bytes)`,
    );
  }
  if (options.aad !== undefined) {
    assertBytesOrString(options.aad, 'options.aad');
  }

  try {
    const decipher = crypto.createDecipheriv(spec.algo, key, options.iv);
    if (spec.spec.mode === 'aead') {
      decipher.setAuthTag(options.tag);
      if (options.aad !== undefined) {
        decipher.setAAD(toBuffer(options.aad, 'options.aad'));
      }
    }
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    throw new CryptoError(
      ErrorCode.DECRYPT_FAILED,
      `authenticated decryption failed — wrong key, tampered ciphertext, wrong iv/tag, or altered AAD. This is an authentication failure, not a bug; treat as unauthorized.`,
      { cause: err },
    );
  }
}

/**
 * Encrypt `data` and pack `iv || tag || ciphertext` into a single URL-safe
 * base64url token. The token is fully self-contained: {@link decryptFromString}
 * needs only the key and the token — nothing else must travel alongside.
 *
 * Ideal for session cookies, magic-link tokens, opaque state tokens.
 *
 * @param {string | Buffer | Uint8Array} data
 * @param {KeyObject}                    key
 * @param {SymmetricOptions}             [options]
 * @returns {string}                     base64url(iv || tag || ciphertext)
 * @throws {CryptoError}                 Same codes as {@link encryptSymmetric}.
 *
 * @example
 * const token = encryptToString('user-state', key)
 * res.cookie('session', token, { httpOnly: true, secure: true })
 */
export function encryptToString(data, key, options) {
  const { ciphertext, iv, tag } = encryptSymmetric(data, key, options);
  return Buffer.concat([iv, tag, ciphertext]).toString('base64url');
}

/**
 * Reverse of {@link encryptToString}. Reads `iv || tag || ciphertext` from
 * a base64url token and decrypts.
 *
 * @param {string}           token
 * @param {KeyObject}        key
 * @param {SymmetricOptions} [options]
 * @returns {Buffer}
 * @throws {CryptoError}     With code:
 *   - `INVALID_ARGUMENT` if `token` is not a string
 *   - `INVALID_CIPHERTEXT` if the packed payload is shorter than iv + tag
 *   - Plus every code {@link decryptSymmetric} may raise (DECRYPT_FAILED, …)
 *
 * @example
 * try {
 *   const plaintext = decryptFromString(cookieValue, key)
 * } catch (err) {
 *   if (err.code === ErrorCode.DECRYPT_FAILED) return res.status(401).end()
 *   throw err
 * }
 */
export function decryptFromString(token, key, options) {
  assertString(token, 'token');
  const spec = _resolveSymmetric(options);
  const packed = Buffer.from(token, 'base64url');
  const minLen = spec.spec.ivLength + spec.spec.tagLength;
  if (packed.length < minLen) {
    throw new CryptoError(
      ErrorCode.INVALID_CIPHERTEXT,
      `token is too short to be a valid ${spec.algo} ciphertext — need at least ${minLen} bytes (iv:${spec.spec.ivLength} + tag:${spec.spec.tagLength}), got ${packed.length} after base64url decode`,
    );
  }
  const iv = packed.subarray(0, spec.spec.ivLength);
  const tag = packed.subarray(spec.spec.ivLength, minLen);
  const ciphertext = packed.subarray(minLen);
  return decryptSymmetric(ciphertext, key, {
    algo: spec.algo,
    iv,
    tag: spec.spec.mode === 'aead' ? tag : undefined,
    aad: options?.aad,
  });
}

/**
 * @private
 * @param {SymmetricOptions | DecryptOptions} [options]
 * @returns {{ algo: SymmetricAlgorithm, spec: typeof SYMMETRIC[SymmetricAlgorithm] }}
 */
function _resolveSymmetric(options) {
  const algo = options?.algo ?? 'aes-256-gcm';
  const spec = SYMMETRIC[algo];
  if (!spec) {
    throw new CryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `options.algo ${JSON.stringify(algo)} is not a supported symmetric algorithm. Expected one of: ${SYMMETRIC_ALGOS.join(', ')}. Prefer aes-256-gcm or chacha20-poly1305 (both AEAD).`,
    );
  }
  return { algo, spec };
}
