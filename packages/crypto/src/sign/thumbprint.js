import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertEncoding, assertKeyObject, assertOptionalObject } from '../internal/validate.js';

/**
 * @typedef {object} ThumbprintOptions
 * @property {'sha256' | 'sha384' | 'sha512'}            [hash='sha256'] Digest algorithm.
 * @property {'hex' | 'base64' | 'base64url' | 'buffer'}  [encoding='base64url']
 *                                                                       Output format —
 *                                                                       base64url matches
 *                                                                       the JWT `kid`
 *                                                                       convention.
 */

/**
 * Compute a stable, short fingerprint of a public key — the JOSE-style
 * "key thumbprint" that JWT `kid` headers and key-rotation dashboards use
 * to identify a key across systems without exposing the key itself.
 *
 * The thumbprint hashes the SubjectPublicKeyInfo DER (Node's `.export`
 * of the public key in `spki` form) and encodes the digest as
 * base64url by default. Two callers with the same public key produce
 * the same thumbprint; a different public key produces a different one.
 *
 * Accepts either a public KeyObject (thumbprint of the key itself) or
 * a private KeyObject (thumbprint of the paired public key — same value
 * as if you called it on the extracted public key).
 *
 * Note: this is a **fingerprint of the DER encoding**, not the strictly
 * canonical RFC 7638 JWK thumbprint (which requires JWK member ordering).
 * For JWT `kid` interop with libraries that also compute over the DER
 * form the two agree; for cross-library JWK interop pass the same key
 * through this helper on both sides.
 *
 * @param {import('node:crypto').KeyObject} key
 * @param {ThumbprintOptions}               [options]
 * @returns {string | Buffer}   Key fingerprint (base64url string by default).
 * @throws {CryptoError} `INVALID_KEY` if `key` is not a KeyObject;
 *                       `UNSUPPORTED_ALGORITHM` if `options.hash` is not recognised.
 *
 * @example
 * const kp = await generateSignKeyPair('es256')
 * const kid = thumbprint(kp.publicKey)
 * const jwt = jsonwebtoken.sign(payload, privateKeyPem, { algorithm: 'ES256', keyid: kid })
 *
 * @example
 * // Key rotation dashboard — human-readable short fingerprint.
 * thumbprint(kp.publicKey, { encoding: 'hex' }).slice(0, 16)  // '3a7f8b2c...'
 */
export function thumbprint(key, options) {
  if (!key || typeof key !== 'object' || (key.type !== 'public' && key.type !== 'private')) {
    throw new CryptoError(ErrorCode.INVALID_KEY, 'key must be a public or private KeyObject');
  }
  assertOptionalObject(options, 'options');
  const hash = options?.hash ?? 'sha256';
  if (hash !== 'sha256' && hash !== 'sha384' && hash !== 'sha512') {
    throw new CryptoError(ErrorCode.UNSUPPORTED_ALGORITHM, "options.hash must be 'sha256', 'sha384', or 'sha512'");
  }
  const encoding = options?.encoding ?? 'base64url';
  assertEncoding(encoding, 'options.encoding');

  // Derive public form when a private key is supplied — the paired public
  // key is what identifies the key across systems.
  const publicKey = key.type === 'private' ? crypto.createPublicKey(key) : key;
  assertKeyObject(publicKey, 'public', 'derived publicKey');

  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const digest = crypto.createHash(hash).update(spki).digest();
  return encoding === 'buffer' ? digest : digest.toString(encoding);
}
