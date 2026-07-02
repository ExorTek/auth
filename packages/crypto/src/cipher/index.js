import { generateKey, generateKeyPair } from './generate.js';
import {
  encryptSymmetric,
  decryptSymmetric,
  encryptToString,
  decryptFromString,
} from './symmetric.js';
import { encryptAsymmetric, decryptAsymmetric } from './asymmetric.js';
import { encryptHybrid, decryptHybrid } from './hybrid.js';
import { deriveSharedSecret } from './derive.js';
import { SYMMETRIC_ALGOS, ASYMMETRIC_ALGOS, KEY_AGREEMENT_ALGOS } from './algorithms.js';
import { CryptoError, ErrorCode } from '../errors.js';

/**
 * Polymorphic encrypt — dispatches based on the key type.
 *
 *   • `secret` KeyObject → symmetric AEAD/CBC (returns `{ ciphertext, iv, tag }`)
 *   • `public` KeyObject → RSA-OAEP (returns a `Buffer`)
 *
 * When the payload shape matters at the call site, prefer the explicit
 * {@link encryptSymmetric} / {@link encryptAsymmetric} variants — the
 * return type is unambiguous and IDE tooling works better.
 *
 * @param {string | Buffer | Uint8Array} data
 * @param {import('node:crypto').KeyObject} key
 * @param {object} [options]
 * @returns {ReturnType<typeof encryptSymmetric> | Buffer}
 */
function encrypt(data, key, options) {
  if (!key || typeof key !== 'object' || typeof key.type !== 'string') {
    throw new CryptoError(ErrorCode.INVALID_KEY, 'key must be a KeyObject');
  }
  if (key.type === 'secret') {
    return encryptSymmetric(data, key, options);
  }
  if (key.type === 'public') {
    return encryptAsymmetric(data, key, {
      algo: options?.algo ?? 'rsa-oaep-256',
    });
  }
  throw new CryptoError(
    ErrorCode.INVALID_KEY,
    'encrypt requires a secret (symmetric) or public (asymmetric) KeyObject',
  );
}

/**
 * Polymorphic decrypt — dispatches based on the key type.
 *
 * When the input shape matters at the call site, prefer the explicit
 * {@link decryptSymmetric} / {@link decryptAsymmetric} variants.
 *
 * @param {Buffer | Uint8Array} ciphertext
 * @param {import('node:crypto').KeyObject} key
 * @param {object} options
 * @returns {Buffer}
 */
function decrypt(ciphertext, key, options) {
  if (!key || typeof key !== 'object' || typeof key.type !== 'string') {
    throw new CryptoError(ErrorCode.INVALID_KEY, 'key must be a KeyObject');
  }
  if (key.type === 'secret') {
    return decryptSymmetric(ciphertext, key, options);
  }
  if (key.type === 'private') {
    return decryptAsymmetric(ciphertext, key, {
      algo: options?.algo ?? 'rsa-oaep-256',
    });
  }
  throw new CryptoError(
    ErrorCode.INVALID_KEY,
    'decrypt requires a secret (symmetric) or private (asymmetric) KeyObject',
  );
}

/**
 * Namespace object grouping every cipher primitive under a single import.
 *
 * @example
 * import { cipher } from '@exortek/crypto/cipher'
 *
 * // Polymorphic (dispatches on key type)
 * const key = await cipher.generateKey()
 * const enc = cipher.encrypt('data', key)
 * const plain = cipher.decrypt(enc.ciphertext, key, { iv: enc.iv, tag: enc.tag })
 *
 * // Explicit symmetric — same primitives, unambiguous return type
 * const { ciphertext, iv, tag } = cipher.encryptSymmetric('data', key)
 * const buf = cipher.decryptSymmetric(ciphertext, key, { iv, tag })
 *
 * // Explicit asymmetric (RSA-OAEP)
 * const { publicKey, privateKey } = await cipher.generateKeyPair('rsa-oaep-256')
 * const encPk = cipher.encryptAsymmetric('msg', publicKey, { algo: 'rsa-oaep-256' })
 * const dec = cipher.decryptAsymmetric(encPk, privateKey, { algo: 'rsa-oaep-256' })
 *
 * // Hybrid, string-shorthand, ECDH — as before.
 */
export const cipher = Object.freeze({
  generateKey,
  generateKeyPair,
  encrypt,
  decrypt,
  encryptSymmetric,
  decryptSymmetric,
  encryptAsymmetric,
  decryptAsymmetric,
  encryptToString,
  decryptFromString,
  encryptHybrid,
  decryptHybrid,
  deriveSharedSecret,
  SYMMETRIC_ALGOS,
  ASYMMETRIC_ALGOS,
  KEY_AGREEMENT_ALGOS,
});

export {
  generateKey,
  generateKeyPair,
  encryptSymmetric,
  decryptSymmetric,
  encryptAsymmetric,
  decryptAsymmetric,
  encryptToString,
  decryptFromString,
  encryptHybrid,
  decryptHybrid,
  deriveSharedSecret,
  SYMMETRIC_ALGOS,
  ASYMMETRIC_ALGOS,
  KEY_AGREEMENT_ALGOS,
};
