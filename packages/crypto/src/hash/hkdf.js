import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertBytesOrString, assertEncoding, assertOptionalObject, assertPositiveInt } from '../internal/validate.js';
import { toBuffer } from '../internal/bytes.js';

/** Supported HKDF underlying hash functions. */
export const SUPPORTED_HKDF_HASHES = /** @type {const} */ (['sha256', 'sha384', 'sha512']);
const _SUPPORTED = new Set(SUPPORTED_HKDF_HASHES);

/** Output length in bytes of each supported hash — HKDF max output is 255 × hashLen. */
const _HASH_LEN = /** @type {const} */ ({ sha256: 32, sha384: 48, sha512: 64 });

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
 *                                                                Capped at `255 × hashLength` for the
 *                                                                chosen `hash`: 8160 (sha256),
 *                                                                12240 (sha384), 16320 (sha512).
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
    throw new CryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `options.hash ${JSON.stringify(hash)} is not supported for HKDF. Expected one of: ${SUPPORTED_HKDF_HASHES.join(', ')}. Prefer sha256.`,
    );
  }
  const length = options?.length ?? 32;
  assertPositiveInt(length, 'options.length');
  // HKDF max output = 255 * hashLen, and hashLen depends on the chosen hash —
  // enforce the real per-hash ceiling so we raise a CryptoError instead of
  // letting Node throw a raw RangeError for e.g. sha256 + length 10000.
  const maxLength = 255 * _HASH_LEN[hash];
  if (length > maxLength) {
    throw new CryptoError(
      ErrorCode.INVALID_ARGUMENT,
      `options.length ${length} exceeds HKDF maximum of ${maxLength} bytes for ${hash} (255 × ${_HASH_LEN[hash]}). For more key material, call hkdf multiple times with distinct info strings.`,
    );
  }
  const salt = options?.salt !== undefined ? toBuffer(options.salt, 'options.salt') : Buffer.alloc(0);
  const info = options?.info !== undefined ? toBuffer(options.info, 'options.info') : Buffer.alloc(0);

  const encoding = options?.encoding ?? 'buffer';
  assertEncoding(encoding, 'options.encoding');

  // hkdfSync returns ArrayBuffer; wrap in Buffer for ergonomic API.
  const derived = Buffer.from(crypto.hkdfSync(hash, toBuffer(ikm, 'ikm'), salt, info, length));
  return encoding === 'buffer' ? derived : derived.toString(encoding);
}
