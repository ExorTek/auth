import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertKeyObject, assertObject } from '../internal/validate.js';
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
 * plaintexts.
 *
 * @param {string | Buffer | Uint8Array} data
 * @param {KeyObject}                    publicKey
 * @param {AsymmetricOptions}            options
 * @returns {Buffer}                     Ciphertext.
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
 * @param {KeyObject}           privateKey
 * @param {AsymmetricOptions}   options
 * @returns {Buffer}                     Plaintext bytes.
 * @throws {CryptoError} With code `DECRYPT_FAILED` on wrong key or malformed ciphertext.
 */
export function decryptAsymmetric(ciphertext, privateKey, options) {
  if (!(ciphertext instanceof Uint8Array)) {
    throw new CryptoError(ErrorCode.INVALID_ARGUMENT, 'ciphertext must be a Buffer');
  }
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
      Buffer.isBuffer(ciphertext) ? ciphertext : Buffer.from(ciphertext),
    );
  } catch (err) {
    throw new CryptoError(ErrorCode.DECRYPT_FAILED, 'RSA-OAEP decryption failed', { cause: err });
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
      `asymmetric algo must be one of: ${ASYMMETRIC_ALGOS.join(', ')}`,
    );
  }
  return spec;
}
