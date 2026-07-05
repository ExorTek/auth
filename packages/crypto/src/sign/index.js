import { generateSignKeyPair } from './generate.js';
import { sign } from './sign.js';
import { verify } from './verify.js';
import { SIGN_ALGOS } from './algorithms.js';

/**
 * Namespace object grouping every signature primitive under a single import.
 *
 * @example
 * import { sign as signNs } from '@exortek/crypto/sign'
 *
 * const { publicKey, privateKey } = await signNs.generateSignKeyPair('es256')
 * const sig = signNs.sign(payload, privateKey, { algo: 'es256' })
 * const ok = signNs.verify(payload, sig, publicKey, { algo: 'es256' })
 */
export const signatures = Object.freeze({
  generateSignKeyPair,
  sign,
  verify,
  SIGN_ALGOS,
});

export { generateSignKeyPair, sign, verify, SIGN_ALGOS };
