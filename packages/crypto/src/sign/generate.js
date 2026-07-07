import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { CryptoError, ErrorCode } from '../errors.js';
import { SIGN, SIGN_ALGOS } from './algorithms.js';

const generateKeyPairAsync = promisify(crypto.generateKeyPair);

/**
 * @typedef {import('node:crypto').KeyObject} KeyObject
 * @typedef {import('./algorithms.js').SignAlgorithm} SignAlgorithm
 */

/**
 * @typedef {object} KeyPair
 * @property {KeyObject} publicKey
 * @property {KeyObject} privateKey
 */

/**
 * Generate an asymmetric key pair matched to a signing algorithm.
 *
 * The returned key material carries the algorithm's parameter metadata
 * (RSA modulus length, EC curve, Ed25519 identifier) so both {@link sign}
 * and {@link verify} operate without further wiring.
 *
 * @param {SignAlgorithm} algo  One of {@link SIGN_ALGOS}.
 * @returns {Promise<KeyPair>}
 * @throws {CryptoError} With code `UNSUPPORTED_ALGORITHM` if `algo` is not recognised.
 *
 * @example
 * const { publicKey, privateKey } = await generateSignKeyPair('es256')
 * const sig = sign(payload, privateKey, { algo: 'es256' })
 */
export async function generateSignKeyPair(algo) {
  const spec = SIGN[algo];
  if (!spec) {
    throw new CryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `generateSignKeyPair algo ${JSON.stringify(algo)} is not supported. Expected one of: ${SIGN_ALGOS.join(', ')}. Recommended defaults: 'es256' (ECDSA P-256) or 'eddsa' (Ed25519).`,
    );
  }
  if (spec.type === 'rsa') {
    return generateKeyPairAsync('rsa', { modulusLength: spec.modulusLength });
  }
  if (spec.type === 'ec') {
    return generateKeyPairAsync('ec', { namedCurve: spec.namedCurve });
  }
  return generateKeyPairAsync('ed25519');
}
