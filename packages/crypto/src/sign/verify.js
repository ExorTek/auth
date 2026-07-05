import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertBytesOrString, assertKeyObject, assertObject } from '../internal/validate.js';
import { toBuffer } from '../internal/bytes.js';
import { _resolveSpec, _keyInput } from './sign.js';

/**
 * @typedef {import('node:crypto').KeyObject} KeyObject
 * @typedef {import('./algorithms.js').SignAlgorithm} SignAlgorithm
 */

/**
 * @typedef {object} VerifyOptions
 * @property {SignAlgorithm}                              algo       Required. Must match the algorithm used at sign time.
 * @property {'hex' | 'base64' | 'base64url'}             [encoding] Encoding of `signature` when it is a string.
 *                                                                   Ignored when a Buffer is passed.
 */

/**
 * Verify an asymmetric signature over `data`.
 *
 * Returns a boolean — a mismatched signature, wrong key, wrong algorithm
 * or tampered data all resolve to `false` without throwing. Only argument
 * or key type errors raise `CryptoError`.
 *
 * @param {string | Buffer | Uint8Array} data       Bytes that were signed.
 * @param {string | Buffer | Uint8Array} signature  Signature to verify. Strings
 *                                                  are decoded per `options.encoding`
 *                                                  (default `'base64url'`).
 * @param {KeyObject}                    publicKey  Public KeyObject matched to `algo`.
 * @param {VerifyOptions}                options
 * @returns {boolean}
 * @throws {CryptoError} With code:
 *   - `INVALID_ARGUMENT` if `data`, `signature` or `options` are missing / wrong type
 *   - `INVALID_KEY` if `publicKey` is not a public KeyObject
 *   - `UNSUPPORTED_ALGORITHM` if `options.algo` is not recognised
 *
 * @example
 * const ok = verify('claim=1', sig, publicKey, { algo: 'es256' })
 * if (!ok) throw new Error('bad signature')
 */
export function verify(data, signature, publicKey, options) {
  assertBytesOrString(data, 'data');
  assertObject(options, 'options');
  const spec = _resolveSpec(options);
  assertKeyObject(publicKey, 'public', 'publicKey');

  let sigBuf;
  if (Buffer.isBuffer(signature) || signature instanceof Uint8Array) {
    sigBuf = Buffer.isBuffer(signature) ? signature : Buffer.from(signature.buffer, signature.byteOffset, signature.byteLength);
  } else if (typeof signature === 'string') {
    const encoding = options.encoding ?? 'base64url';
    if (encoding !== 'hex' && encoding !== 'base64' && encoding !== 'base64url') {
      throw new CryptoError(ErrorCode.INVALID_ARGUMENT, "options.encoding must be 'hex', 'base64', or 'base64url'");
    }
    sigBuf = Buffer.from(signature, encoding);
  } else {
    throw new CryptoError(ErrorCode.INVALID_ARGUMENT, 'signature must be a string or Buffer');
  }

  const dataBuf = toBuffer(data, 'data');
  const keyInput = _keyInput(publicKey, spec);

  try {
    return crypto.verify(spec.hash, dataBuf, keyInput, sigBuf);
  } catch {
    // Node throws on malformed ASN.1 signatures — semantically that's just
    // "invalid signature", not a programmer error, so we swallow and return false.
    return false;
  }
}
