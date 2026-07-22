import { generateKey, generateKeyPair } from './generate.js';
import { encryptSymmetric, decryptSymmetric, encryptToString, decryptFromString } from './symmetric.js';
import { encryptAsymmetric, decryptAsymmetric } from './asymmetric.js';
import { encryptHybrid, decryptHybrid } from './hybrid.js';
import { deriveSharedSecret } from './derive.js';
import { encryptWithPassphrase, decryptWithPassphrase } from './passphrase.js';
import { seal, unseal } from './seal.js';
import { SYMMETRIC_ALGOS, ASYMMETRIC_ALGOS, KEY_AGREEMENT_ALGOS } from './algorithms.js';
import { invalidKey } from '../internal/guards.js';
import { _keyProblemHint } from '../internal/validate.js';

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
    throw invalidKey(`key must be a KeyObject; ${_keyProblemHint(key)}`);
  }
  if (key.type === 'secret') {
    return encryptSymmetric(data, key, options);
  }
  if (key.type === 'public') {
    return encryptAsymmetric(data, key, {
      algo: options?.algo ?? 'rsa-oaep-256',
    });
  }
  throw invalidKey(
    `encrypt requires a secret (symmetric) or public (asymmetric) KeyObject; got a ${key.type} KeyObject`,
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
    throw invalidKey(`key must be a KeyObject; ${_keyProblemHint(key)}`);
  }
  if (key.type === 'secret') {
    return decryptSymmetric(ciphertext, key, options);
  }
  if (key.type === 'private') {
    return decryptAsymmetric(ciphertext, key, {
      algo: options?.algo ?? 'rsa-oaep-256',
    });
  }
  throw invalidKey(
    `decrypt requires a secret (symmetric) or private (asymmetric) KeyObject; got a ${key.type} KeyObject`,
  );
}

/**
 * Namespace object grouping every cipher primitive under a single import.
 *
 * @example
 * import { cipher } from '@exortek/crypto/cipher'
 *
 * // Symmetric with a KeyObject
 * const key = await cipher.generateKey()
 * const { ciphertext, iv, tag } = cipher.encryptSymmetric('data', key)
 *
 * // Password-Based Encryption — no key management
 * const token = await cipher.encryptWithPassphrase('data', 'my-passphrase')
 * const plain = await cipher.decryptWithPassphrase(token, 'my-passphrase')
 *
 * // Asymmetric (RSA-OAEP) / Hybrid / Key agreement — as documented in
 * // the module JSDoc for each function.
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
  encryptWithPassphrase,
  decryptWithPassphrase,
  deriveSharedSecret,
  seal,
  unseal,
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
  encryptWithPassphrase,
  decryptWithPassphrase,
  deriveSharedSecret,
  seal,
  unseal,
  SYMMETRIC_ALGOS,
  ASYMMETRIC_ALGOS,
  KEY_AGREEMENT_ALGOS,
};
