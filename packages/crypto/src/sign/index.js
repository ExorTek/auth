import { generateSignKeyPair } from './generate.js';
import { sign } from './sign.js';
import { verify } from './verify.js';
import { thumbprint } from './thumbprint.js';
import { SIGN_ALGOS } from './algorithms.js';

/**
 * Namespace object grouping every signature primitive under a single import.
 */
export const signatures = Object.freeze({
  generateSignKeyPair,
  sign,
  verify,
  thumbprint,
  SIGN_ALGOS,
});

export { generateSignKeyPair, sign, verify, thumbprint, SIGN_ALGOS };
