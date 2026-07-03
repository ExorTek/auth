import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertKeyObject, assertOptionalObject } from '../internal/validate.js';
import { toBuffer } from '../internal/bytes.js';

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

  const length = options?.length ?? 32;
  if (!Number.isSafeInteger(length) || length <= 0 || length > 255 * 32) {
    // HKDF-SHA256 caps at 255 × hashLen; conservatively require > 0 and reasonable.
    throw new CryptoError(
      ErrorCode.INVALID_ARGUMENT,
      'options.length must be a positive safe integer within HKDF limits',
    );
  }
  const info = options?.info !== undefined ? toBuffer(options.info, 'options.info') : Buffer.alloc(0);
  const salt = options?.salt !== undefined ? toBuffer(options.salt, 'options.salt') : Buffer.alloc(0);
  const hash = options?.hash ?? 'sha256';
  if (!['sha256', 'sha384', 'sha512'].includes(hash)) {
    throw new CryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      "options.hash must be 'sha256', 'sha384' or 'sha512'",
    );
  }

  try {
    const shared = crypto.diffieHellman({ privateKey, publicKey });
    // hkdfSync returns an ArrayBuffer; wrap in Buffer for ergonomic API.
    return Buffer.from(crypto.hkdfSync(hash, shared, salt, info, length));
  } catch (err) {
    throw new CryptoError(ErrorCode.INVALID_KEY, 'key agreement failed — mismatched curves?', {
      cause: err,
    });
  }
}
