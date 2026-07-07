import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertBytesOrString, assertEncoding, assertOptionalObject, assertPositiveInt } from '../internal/validate.js';
import { toBuffer } from '../internal/bytes.js';

/** Supported HKDF underlying hash functions. */
export const SUPPORTED_HKDF_HASHES = /** @type {const} */ (['sha256', 'sha384', 'sha512']);
const _SUPPORTED = new Set(SUPPORTED_HKDF_HASHES);

/**
 * @typedef {object} HkdfOptions
 * @property {string | Buffer | Uint8Array}      [salt='']       Random salt. Empty by default;
 *                                                                fine for most uses since HKDF's
 *                                                                security does not require a
 *                                                                secret salt.
 * @property {string | Buffer | Uint8Array}      [info='']       Context / application info string.
 *                                                                Use this for domain separation
 *                                                                when deriving multiple keys from
 *                                                                the same IKM (e.g. `'session'` vs
 *                                                                `'refresh'` vs `'csrf'`).
 * @property {number}                            [length=32]     Output length in bytes.
 *                                                                Capped at `255 × hashLength`
 *                                                                (255 × 32 = 8160 for SHA-256).
 * @property {'sha256' | 'sha384' | 'sha512'}    [hash='sha256'] Underlying hash function.
 * @property {'hex' | 'base64' | 'base64url' | 'buffer'} [encoding='buffer']
 *                                                                Output format.
 */

/**
 * HKDF (RFC 5869) — extract-and-expand key derivation from high-entropy
 * input keying material (IKM).
 *
 * Use HKDF whenever you already have strong key material (a random
 * secret, a DH-shared secret, a master key) and want to derive one or
 * more distinct, uniformly-distributed subkeys from it. The `info`
 * parameter provides **domain separation** — same IKM + different info
 * = cryptographically independent keys.
 *
 * **Not for passwords.** HKDF assumes the IKM already has ≥ hashLength
 * bits of entropy. For low-entropy secrets (user passphrases) use
 * {@link pbkdf2} instead.
 *
 * @param {string | Buffer | Uint8Array} ikm   Input keying material.
 * @param {HkdfOptions}                  [options]
 * @returns {string | Buffer}   Derived key (Buffer by default).
 * @throws {CryptoError}   With code:
 *   - `INVALID_ARGUMENT` on bad inputs or `length` outside HKDF limits
 *   - `UNSUPPORTED_ALGORITHM` if `hash` is not in {@link SUPPORTED_HKDF_HASHES}
 *
 * @example
 * // Derive two independent keys from the same master secret:
 * const encKey = hkdf(masterSecret, { info: 'encryption', length: 32 })
 * const macKey = hkdf(masterSecret, { info: 'authentication', length: 32 })
 *
 * @example
 * // Session key with salt + application context:
 * const sessionKey = hkdf(sharedSecret, {
 *   salt: userId,
 *   info: 'session-v1',
 *   length: 32,
 * })
 */
export function hkdf(ikm, options) {
  assertBytesOrString(ikm, 'ikm');
  assertOptionalObject(options, 'options');

  const hash = options?.hash ?? 'sha256';
  if (!_SUPPORTED.has(hash)) {
    throw new CryptoError(ErrorCode.UNSUPPORTED_ALGORITHM, `hash must be one of: ${SUPPORTED_HKDF_HASHES.join(', ')}`);
  }
  const length = options?.length ?? 32;
  assertPositiveInt(length, 'options.length');
  // HKDF max output = 255 * hashLen. Conservative upper bound (SHA-256 hashLen = 32).
  if (length > 255 * 64) {
    throw new CryptoError(ErrorCode.INVALID_ARGUMENT, 'options.length exceeds HKDF maximum (255 × hashLength)');
  }
  const salt = options?.salt !== undefined ? toBuffer(options.salt, 'options.salt') : Buffer.alloc(0);
  const info = options?.info !== undefined ? toBuffer(options.info, 'options.info') : Buffer.alloc(0);

  const encoding = options?.encoding ?? 'buffer';
  assertEncoding(encoding, 'options.encoding');

  // hkdfSync returns ArrayBuffer; wrap in Buffer for ergonomic API.
  const derived = Buffer.from(crypto.hkdfSync(hash, toBuffer(ikm, 'ikm'), salt, info, length));
  return encoding === 'buffer' ? derived : derived.toString(encoding);
}
