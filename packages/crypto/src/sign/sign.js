import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertBytesOrString, assertEncoding, assertObject } from '../internal/guards.js';
import { toBuffer } from '../internal/bytes.js';
import { SIGN, SIGN_ALGOS } from './algorithms.js';
import { assertKeyObject } from '../internal/validate.js';

/**
 * @typedef {import('node:crypto').KeyObject} KeyObject
 * @typedef {import('./algorithms.js').SignAlgorithm} SignAlgorithm
 */

/**
 * @typedef {object} SignOptions
 * @property {SignAlgorithm} algo   One of {@link SIGN_ALGOS}. Required.
 * @property {'hex' | 'base64' | 'base64url' | 'buffer'} [encoding='buffer']
 *                                  Output signature encoding.
 */

/**
 * Compute an asymmetric signature over `data`.
 *
 * Supports the full JOSE-standard family:
 *
 *   - `rs256`/`rs384`/`rs512` — RSASSA-PKCS1-v1_5 with SHA-2 (legacy JWT default)
 *   - `ps256`/`ps384`/`ps512` — RSASSA-PSS with SHA-2 (modern RSA choice)
 *   - `es256`/`es384`/`es512` — ECDSA on P-256/P-384/P-521 with SHA-2
 *   - `eddsa` — Ed25519 (Edwards-curve DSA, no external hash)
 *
 * The key must be a private KeyObject matched to the algorithm's key type;
 * generate one with {@link generateSignKeyPair}. For JWT/JWS interop the
 * algorithm name maps 1:1 to the JOSE `alg` header value (`RS256` etc.),
 * but the library uses lowercase to stay consistent with the rest of the
 * `@exortek/crypto` surface.
 *
 * @param {string | Buffer | Uint8Array} data       Bytes to sign.
 * @param {KeyObject}                    privateKey Private KeyObject.
 * @param {SignOptions}                  options
 * @returns {string | Buffer}   Signature (raw bytes by default).
 * @throws {CryptoError} With code:
 *   - `INVALID_ARGUMENT` if `data` or `options` are missing / wrong type
 *   - `INVALID_KEY` if `privateKey` is not a private KeyObject
 *   - `UNSUPPORTED_ALGORITHM` if `options.algo` is not in {@link SIGN_ALGOS}
 *
 * @example
 * const { publicKey, privateKey } = await generateSignKeyPair('es256')
 * const sig = sign('claim=1', privateKey, { algo: 'es256' })
 * // → Buffer<...>
 *
 * @example
 * // Base64url encoded for JWS-style transport:
 * const sigStr = sign(header + '.' + payload, sk, { algo: 'ps256', encoding: 'base64url' })
 */
export function sign(data, privateKey, options) {
  assertBytesOrString(data, 'data');
  assertObject(options, 'options');
  const spec = _resolveSpec(options);
  assertKeyObject(privateKey, 'private', 'privateKey');

  const encoding = options.encoding ?? 'buffer';
  assertEncoding(encoding, 'options.encoding');

  const dataBuf = toBuffer(data, 'data');
  const keyInput = _keyInput(privateKey, spec);

  const signature = crypto.sign(spec.hash, dataBuf, keyInput);
  return encoding === 'buffer' ? signature : signature.toString(encoding);
}

/**
 * Build the Node crypto key input for sign/verify.
 * - RSA-PSS: bake in RSA_PSS_SALTLEN_DIGEST so callers don't juggle constants.
 * - ECDSA:   force IEEE-P1363 (raw R||S) encoding — the JOSE / JWS format,
 *            not Node's default DER. Downstream JWT libraries expect this.
 * - Otherwise: pass the KeyObject through directly.
 * @private
 */
export function _keyInput(key, spec) {
  if (spec.padding !== undefined) {
    return { key, padding: spec.padding, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST };
  }
  if (spec.type === 'ec') {
    return { key, dsaEncoding: 'ieee-p1363' };
  }
  return key;
}

/**
 * @private
 */
function _resolveSpec(options) {
  const spec = SIGN[options.algo];
  if (!spec) {
    throw new CryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `options.algo ${JSON.stringify(options.algo)} is not a supported signing algorithm. Expected one of: ${SIGN_ALGOS.join(', ')}. For symmetric MAC use hmac(); for signing use one of these JOSE algorithms.`,
    );
  }
  return spec;
}

export { _resolveSpec };
