import crypto from 'node:crypto';

import { isBuffer } from '@exortek/shared/predicates';

import { CryptoError, ErrorCode } from '../errors.js';
import { assertBytes, assertObject } from '../internal/guards.js';

import { assertKeyObject } from '../internal/validate.js';
import { toBuffer } from '../internal/bytes.js';
import { ASYMMETRIC, ASYMMETRIC_ALGOS } from './algorithms.js';

/**
 * @typedef {import('node:crypto').KeyObject} KeyObject
 * @typedef {import('./algorithms.js').AsymmetricAlgorithm} AsymmetricAlgorithm
 */

/**
 * @typedef {object} AsymmetricOptions
 * @property {AsymmetricAlgorithm} algo  `'rsa-oaep'` or `'rsa-oaep-256'`.
 */

/**
 * RSA-OAEP encrypt `data` with a public key.
 *
 * Suitable for small payloads (a few hundred bytes at most — RSA is not
 * designed for bulk data). Use {@link encryptHybrid} to seal larger
 * plaintexts. Each call uses fresh OAEP padding, so the same plaintext
 * yields distinct ciphertexts (semantic security).
 *
 * @param {string | Buffer | Uint8Array} data
 * @param {KeyObject}                    publicKey  RSA public key from {@link generateKeyPair}.
 * @param {AsymmetricOptions}            options    `options.algo` is required.
 * @returns {Buffer}                     Ciphertext.
 * @throws {CryptoError}  With code:
 *   - `INVALID_ARGUMENT` for bad `data` or missing `options`
 *   - `INVALID_KEY` if `publicKey` is not a public KeyObject
 *   - `UNSUPPORTED_ALGORITHM` for unknown `options.algo`
 *
 * @example
 * const { publicKey } = await generateKeyPair('rsa-oaep-256')
 * const enc = encryptAsymmetric('shared-secret', publicKey, { algo: 'rsa-oaep-256' })
 */
export function encryptAsymmetric(data, publicKey, options) {
  assertObject(options, 'options');
  const spec = _resolveAsymmetric(options);
  assertKeyObject(publicKey, 'public', 'publicKey');

  return crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: spec.hash,
    },
    toBuffer(data, 'data'),
  );
}

/**
 * RSA-OAEP decrypt a ciphertext with a private key.
 *
 * @param {Buffer | Uint8Array} ciphertext
 * @param {KeyObject}           privateKey  RSA private key from {@link generateKeyPair}.
 * @param {AsymmetricOptions}   options     Must specify the same `algo` used at encryption.
 * @returns {Buffer}                        Plaintext bytes.
 * @throws {CryptoError}  With code:
 *   - `INVALID_ARGUMENT` for missing / wrong-type `ciphertext` or `options`
 *   - `INVALID_KEY` if `privateKey` is not a private KeyObject
 *   - `UNSUPPORTED_ALGORITHM` for unknown `options.algo`
 *   - `DECRYPT_FAILED` on wrong key or malformed ciphertext
 *
 * @example
 * const plaintext = decryptAsymmetric(enc, privateKey, { algo: 'rsa-oaep-256' })
 */
export function decryptAsymmetric(ciphertext, privateKey, options) {
  assertBytes(ciphertext, 'ciphertext', { hint: 'pass the exact bytes returned by encryptAsymmetric().' });
  assertObject(options, 'options');
  const spec = _resolveAsymmetric(options);
  assertKeyObject(privateKey, 'private', 'privateKey');

  try {
    return crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: spec.hash,
      },
      isBuffer(ciphertext) ? ciphertext : Buffer.from(ciphertext),
    );
  } catch (err) {
    throw new CryptoError(
      ErrorCode.DECRYPT_FAILED,
      'RSA-OAEP decryption failed — wrong key, corrupted ciphertext, or an OAEP hash mismatch (encrypt and decrypt must both use options.algo=rsa-oaep-256 or both rsa-oaep). Never render this hint to the caller.',
      { cause: err },
    );
  }
}

/**
 * @private
 */
function _resolveAsymmetric(options) {
  const spec = ASYMMETRIC[options.algo];
  if (!spec) {
    throw new CryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `options.algo ${JSON.stringify(options.algo)} is not a supported asymmetric algorithm. Expected one of: ${ASYMMETRIC_ALGOS.join(', ')}. Prefer 'rsa-oaep-256' (SHA-256 padding).`,
    );
  }
  return spec;
}
