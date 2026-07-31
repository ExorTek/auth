/**
 * Key material normaliser — turn JWK objects, `KeyObject`s, PEM strings,
 * and raw `Buffer` / `Uint8Array` secrets into the concrete shape each
 * key-management family needs: a `Buffer` for the symmetric families
 * (`dir`, AES-KW) and a `KeyObject` for the asymmetric ones (RSA-OAEP,
 * ECDH-ES). Shape mismatches surface as {@link ErrorCode.INVALID_KEY}
 * at the boundary rather than as a cryptic error deep in `node:crypto`.
 */

import { createPublicKey, createPrivateKey, KeyObject } from 'node:crypto';
import { isObject, isBytes, isString } from '@exortek/shared/predicates';
import { JweError, ErrorCode } from './errors.js';
import { decode as b64uDecode } from './base64url.js';

/**
 * @typedef {import('node:crypto').KeyObject | Buffer | Uint8Array | string | Record<string, unknown>} KeyInput
 */

/**
 * Normalise caller-supplied symmetric key material to a `Buffer` of the
 * exact expected length.
 *
 * @param {KeyInput} key
 * @param {number} expectedBytes
 * @param {string} label  Human context for the error message (`alg`).
 * @returns {Buffer}
 */
export function normalizeSymmetric(key, expectedBytes, label) {
  let bytes;
  if (isBytes(key)) {
    bytes = Buffer.from(/** @type {Buffer | Uint8Array} */ (key));
  } else if (key instanceof KeyObject) {
    if (key.type !== 'secret') {
      throw new JweError(ErrorCode.INVALID_KEY, `${label}: expected a secret KeyObject, got a ${key.type} key.`);
    }
    bytes = key.export();
  } else if (isObject(key) && key.kty === 'oct' && isString(key.k)) {
    bytes = b64uDecode(/** @type {string} */ (key.k));
  } else {
    throw new JweError(
      ErrorCode.INVALID_KEY,
      `${label}: expected symmetric key material — a Buffer/Uint8Array, an oct JWK, or a secret KeyObject.`,
    );
  }
  if (bytes.length !== expectedBytes) {
    throw new JweError(
      ErrorCode.INVALID_KEY,
      `${label}: key must be ${expectedBytes} bytes for this algorithm, got ${bytes.length}.`,
    );
  }
  return bytes;
}

/**
 * Normalise caller-supplied key material to a public `KeyObject` (used
 * when encrypting). A private key / JWK is accepted and reduced to its
 * public half.
 *
 * @param {KeyInput} key
 * @returns {KeyObject}
 */
export function normalizePublicKey(key) {
  if (key instanceof KeyObject) {
    if (key.type === 'public') {
      return key;
    }
    if (key.type === 'private') {
      return createPublicKey(key);
    }
    throw new JweError(ErrorCode.INVALID_KEY, 'expected a public or private KeyObject, got a secret key.');
  }
  try {
    if (isObject(key)) {
      // A JWK carrying `d` is private; reduce it to the public key.
      return isString(key.d)
        ? createPublicKey(createPrivateKey({ key, format: 'jwk' }))
        : createPublicKey({ key, format: 'jwk' });
    }
    if (isString(key)) {
      // PEM — public directly, or a private PEM reduced to its public half.
      try {
        return createPublicKey(key);
      } catch {
        return createPublicKey(createPrivateKey(key));
      }
    }
  } catch (err) {
    throw new JweError(
      ErrorCode.INVALID_KEY,
      `could not read public key — ${err instanceof Error ? err.message : String(err)}`,
      {
        cause: err,
      },
    );
  }
  throw new JweError(ErrorCode.INVALID_KEY, 'expected a KeyObject, JWK, or PEM string for asymmetric key management.');
}

/**
 * Normalise caller-supplied key material to a private `KeyObject` (used
 * when decrypting).
 *
 * @param {KeyInput} key
 * @returns {KeyObject}
 */
export function normalizePrivateKey(key) {
  if (key instanceof KeyObject) {
    if (key.type === 'private') {
      return key;
    }
    throw new JweError(ErrorCode.INVALID_KEY, `decryption needs a private key, got a ${key.type} key.`);
  }
  try {
    if (isObject(key)) {
      if (!isString(key.d)) {
        throw new JweError(ErrorCode.INVALID_KEY, 'decryption needs a private JWK (missing "d").');
      }
      return createPrivateKey({ key, format: 'jwk' });
    }
    if (isString(key)) {
      return createPrivateKey(key);
    }
  } catch (err) {
    if (err instanceof JweError) {
      throw err;
    }
    throw new JweError(
      ErrorCode.INVALID_KEY,
      `could not read private key — ${err instanceof Error ? err.message : String(err)}`,
      {
        cause: err,
      },
    );
  }
  throw new JweError(ErrorCode.INVALID_KEY, 'expected a KeyObject, JWK, or PEM string for asymmetric key management.');
}

/**
 * Assert a public key is RSA and (best-effort) at least 2048-bit, per
 * RFC 7518 §4.3 guidance.
 *
 * @param {KeyObject} key
 */
export function assertRsaPublicKey(key) {
  if (key.asymmetricKeyType !== 'rsa') {
    throw new JweError(
      ErrorCode.INVALID_KEY,
      `RSA-OAEP requires an RSA key, got ${key.asymmetricKeyType ?? 'a non-asymmetric key'}.`,
    );
  }
  const modulusLength = key.asymmetricKeyDetails?.modulusLength;
  if (typeof modulusLength === 'number' && modulusLength < 2048) {
    throw new JweError(
      ErrorCode.INVALID_KEY,
      `RSA-OAEP requires a modulus of at least 2048 bits, got ${modulusLength}.`,
    );
  }
}
