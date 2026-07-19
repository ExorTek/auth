import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertBytes, assertBytesOrString, assertObject, assertOptionalObject } from '../internal/guards.js';
import { toBuffer } from '../internal/bytes.js';
import { encryptAsymmetric, decryptAsymmetric } from './asymmetric.js';

/**
 * @typedef {import('node:crypto').KeyObject} KeyObject
 * @typedef {import('./algorithms.js').AsymmetricAlgorithm} AsymmetricAlgorithm
 */

/**
 * @typedef {object} HybridEnvelope
 * @property {Buffer} encryptedKey  32-byte AES key sealed with RSA-OAEP.
 * @property {Buffer} iv            12-byte AES-GCM nonce.
 * @property {Buffer} tag           16-byte AES-GCM auth tag.
 * @property {Buffer} ciphertext    AES-GCM ciphertext of the plaintext.
 */

/**
 * @typedef {object} HybridOptions
 * @property {AsymmetricAlgorithm} [algo='rsa-oaep-256']  RSA-OAEP variant used
 *                                                        to wrap the AES key.
 */

/**
 * Hybrid encryption — encrypt the plaintext with a fresh AES-256-GCM key,
 * then wrap that AES key with RSA-OAEP under the recipient's public key.
 *
 * Use this whenever the plaintext is larger than the RSA modulus can
 * safely carry (a few hundred bytes) — hybrid gives you the confidentiality
 * / integrity of AES-GCM with the "no shared secret needed" property of RSA.
 *
 * The returned envelope carries every byte the recipient needs; nothing
 * else must be transmitted alongside.
 *
 * @param {string | Buffer | Uint8Array} data
 * @param {KeyObject}                    publicKey  Recipient's RSA public key.
 * @param {HybridOptions}                [options]
 * @returns {HybridEnvelope}
 * @throws {CryptoError}  With code:
 *   - `INVALID_ARGUMENT` for bad `data` or `options`
 *   - `INVALID_KEY` if `publicKey` is not a public KeyObject
 *   - `UNSUPPORTED_ALGORITHM` for unknown `options.algo`
 *
 * @example
 * const { publicKey } = await generateKeyPair('rsa-oaep-256')
 * const envelope = encryptHybrid(largePayload, publicKey)
 * // Ship the envelope (all four Buffers) to the recipient.
 */
export function encryptHybrid(data, publicKey, options) {
  assertBytesOrString(data, 'data');
  assertOptionalObject(options, 'options');
  const algo = options?.algo ?? 'rsa-oaep-256';

  // Fresh 256-bit AES key + 96-bit IV.
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const ciphertext = Buffer.concat([cipher.update(toBuffer(data, 'data')), cipher.final()]);
  const tag = cipher.getAuthTag();

  const encryptedKey = encryptAsymmetric(aesKey, publicKey, { algo });
  return { encryptedKey, iv, tag, ciphertext };
}

/**
 * Reverse of {@link encryptHybrid} — unwrap the AES key with RSA-OAEP,
 * then decrypt the ciphertext with AES-GCM. Both steps are authenticated,
 * so any tampering with the envelope raises `DECRYPT_FAILED` before any
 * plaintext is produced.
 *
 * @param {HybridEnvelope}  envelope
 * @param {KeyObject}       privateKey  Recipient's RSA private key.
 * @param {HybridOptions}   [options]
 * @returns {Buffer}                    Plaintext bytes.
 * @throws {CryptoError}  With code:
 *   - `INVALID_ARGUMENT` if `envelope` fields are missing or wrong type
 *   - `INVALID_KEY` if `privateKey` is not a private KeyObject
 *   - `DECRYPT_FAILED` on tampering, wrong key, or bad OAEP unwrapping
 *
 * @example
 * const plaintext = decryptHybrid(envelope, privateKey)
 */
export function decryptHybrid(envelope, privateKey, options) {
  assertObject(envelope, 'envelope');
  for (const field of ['encryptedKey', 'iv', 'tag', 'ciphertext']) {
    assertBytes(envelope[field], `envelope.${field}`, {
      hint: 'pass the same object shape returned by encryptHybrid(): { encryptedKey, iv, tag, ciphertext }',
    });
  }
  assertOptionalObject(options, 'options');
  const algo = options?.algo ?? 'rsa-oaep-256';

  const aesKey = decryptAsymmetric(envelope.encryptedKey, privateKey, { algo });
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, envelope.iv);
    decipher.setAuthTag(envelope.tag);
    return Buffer.concat([decipher.update(envelope.ciphertext), decipher.final()]);
  } catch (err) {
    throw new CryptoError(
      ErrorCode.DECRYPT_FAILED,
      'hybrid AES-GCM decryption failed — the RSA-wrapped key unwrapped correctly but the AES stage rejected the ciphertext. Wrong iv, wrong tag, or tampered ciphertext.',
      { cause: err },
    );
  }
}
