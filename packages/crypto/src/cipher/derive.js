import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertKeyObject, assertOptionalObject } from '../internal/validate.js';
import { hkdf } from '../hash/hkdf.js';

/**
 * @typedef {import('node:crypto').KeyObject} KeyObject
 */

/**
 * @typedef {object} DeriveOptions
 * @property {number}                        [length=32]  Derived key length in bytes.
 * @property {string | Buffer | Uint8Array}  [info='']    Application context (HKDF info).
 * @property {string | Buffer | Uint8Array}  [salt='']    HKDF salt (optional; usually empty).
 * @property {'sha256' | 'sha384' | 'sha512'} [hash='sha256']  HKDF underlying hash.
 */

/**
 * Derive a symmetric shared secret from an ECDH / X25519 key pair.
 *
 * The raw Diffie–Hellman output is fed through HKDF (RFC 5869) to produce
 * a fixed-length, uniformly-distributed key suitable for use with
 * {@link encryptSymmetric}. This is the recommended pattern — never use
 * the raw DH output directly, since it retains structure from the
 * underlying curve arithmetic (biased distribution).
 *
 * Use `options.info` for domain separation when the same key pair drives
 * multiple derived keys (e.g. one for authentication, one for encryption):
 * different `info` values produce cryptographically independent keys.
 *
 * @param {KeyObject}     privateKey  Local private key from {@link generateKeyPair}.
 * @param {KeyObject}     publicKey   Remote public key. Must use the same curve.
 * @param {DeriveOptions} [options]
 * @returns {Buffer}                  Derived key of `options.length` bytes (default 32).
 * @throws {CryptoError}  With code:
 *   - `INVALID_KEY` if either key is not a matching-curve KeyObject
 *   - `INVALID_ARGUMENT` if `options.length` is outside HKDF limits
 *   - `UNSUPPORTED_ALGORITHM` if `options.hash` is unknown
 *
 * @example
 * // Simple session-key exchange:
 * const alice = await generateKeyPair('x25519')
 * const bob = await generateKeyPair('x25519')
 * const sessionKey = deriveSharedSecret(alice.privateKey, bob.publicKey)
 *
 * @example
 * // Domain-separated keys from the same pair:
 * const encKey = deriveSharedSecret(sk, pk, { info: 'encryption' })
 * const macKey = deriveSharedSecret(sk, pk, { info: 'authentication' })
 */
export function deriveSharedSecret(privateKey, publicKey, options) {
  assertKeyObject(privateKey, 'private', 'privateKey');
  assertKeyObject(publicKey, 'public', 'publicKey');
  assertOptionalObject(options, 'options');

  let shared;
  try {
    shared = crypto.diffieHellman({ privateKey, publicKey });
  } catch (err) {
    throw new CryptoError(
      ErrorCode.INVALID_KEY,
      'key agreement failed — the two keys are on different curves or use incompatible algorithms. Both sides must use the same generateKeyPair(algo) — e.g. both x25519, or both ecdh-p256.',
      { cause: err },
    );
  }

  // Delegate to the public hkdf() helper — same primitive both places, single
  // source of truth for validation and error codes.
  return /** @type {Buffer} */ (
    hkdf(shared, {
      salt: options?.salt,
      info: options?.info,
      length: options?.length ?? 32,
      hash: options?.hash ?? 'sha256',
      encoding: 'buffer',
    })
  );
}
