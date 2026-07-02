import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { CryptoError, ErrorCode } from '../errors.js';
import {
  ASYMMETRIC,
  KEY_AGREEMENT,
  SYMMETRIC,
  SYMMETRIC_ALGOS,
  ASYMMETRIC_ALGOS,
  KEY_AGREEMENT_ALGOS,
} from './algorithms.js';

const generateKeyPairAsync = promisify(crypto.generateKeyPair);
const generateSecretKeyAsync = promisify(crypto.generateKey);

/**
 * @typedef {import('node:crypto').KeyObject} KeyObject
 * @typedef {import('./algorithms.js').SymmetricAlgorithm} SymmetricAlgorithm
 * @typedef {import('./algorithms.js').AsymmetricAlgorithm} AsymmetricAlgorithm
 * @typedef {import('./algorithms.js').KeyAgreementAlgorithm} KeyAgreementAlgorithm
 */

/**
 * @typedef {object} KeyPair
 * @property {KeyObject} publicKey
 * @property {KeyObject} privateKey
 */

/**
 * Generate a fresh symmetric secret key.
 *
 * Returns a Node `KeyObject` bound to the specified algorithm — the
 * returned key carries its own size metadata and is directly usable with
 * {@link encrypt} / {@link decrypt} without further wiring.
 *
 * @param {SymmetricAlgorithm} [algo='aes-256-gcm']
 * @returns {Promise<KeyObject>}
 * @throws {CryptoError} With code `UNSUPPORTED_ALGORITHM` if `algo` is not recognised.
 *
 * @example
 * const key = await generateKey()                     // AES-256-GCM
 * const chachaKey = await generateKey('chacha20-poly1305')
 */
export async function generateKey(algo = 'aes-256-gcm') {
  const spec = SYMMETRIC[algo];
  if (!spec) {
    throw new CryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `symmetric algo must be one of: ${SYMMETRIC_ALGOS.join(', ')}`,
    );
  }
  // Node's generateKey only accepts 'aes' or 'hmac' families; for ChaCha20 we
  // draw raw random bytes and wrap into a KeyObject. Same end result: a bound
  // secret KeyObject of the correct length for the chosen cipher.
  if (algo === 'chacha20-poly1305') {
    return crypto.createSecretKey(crypto.randomBytes(spec.keyLength));
  }
  return generateSecretKeyAsync('aes', { length: spec.keyLength * 8 });
}

/**
 * Generate an asymmetric key pair for RSA-OAEP, ECDH or X25519.
 *
 * @param {AsymmetricAlgorithm | KeyAgreementAlgorithm} algo
 * @returns {Promise<KeyPair>}
 * @throws {CryptoError} With code `UNSUPPORTED_ALGORITHM` if `algo` is not recognised.
 *
 * @example
 * const { publicKey, privateKey } = await generateKeyPair('rsa-oaep-256')
 * const { publicKey: alicePk, privateKey: aliceSk } = await generateKeyPair('x25519')
 */
export async function generateKeyPair(algo) {
  const rsaSpec = ASYMMETRIC[algo];
  if (rsaSpec) {
    return generateKeyPairAsync('rsa', { modulusLength: rsaSpec.modulusLength });
  }
  const kaSpec = KEY_AGREEMENT[algo];
  if (kaSpec) {
    if (kaSpec.type === 'x25519') {
      return generateKeyPairAsync('x25519');
    }
    return generateKeyPairAsync('ec', { namedCurve: kaSpec.namedCurve });
  }
  throw new CryptoError(
    ErrorCode.UNSUPPORTED_ALGORITHM,
    `key-pair algo must be one of: ${[...ASYMMETRIC_ALGOS, ...KEY_AGREEMENT_ALGOS].join(', ')}`,
  );
}
