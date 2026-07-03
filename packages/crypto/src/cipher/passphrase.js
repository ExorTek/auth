import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertBytesOrString, assertOptionalObject, assertString } from '../internal/validate.js';
import { toBuffer } from '../internal/bytes.js';
import { pbkdf2 } from '../hash/pbkdf2.js';

// Fixed layout for the packed token:
//   [0..15]  salt   (16 bytes)
//   [16..27] iv     (12 bytes — AES-GCM nonce)
//   [28..43] tag    (16 bytes — AES-GCM auth tag)
//   [44..]   ciphertext
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const HEADER_LENGTH = SALT_LENGTH + IV_LENGTH + TAG_LENGTH;

// KDF defaults — OWASP 2023 for PBKDF2-SHA512.
const DEFAULT_ITERATIONS = 210_000;
const DEFAULT_KDF_DIGEST = 'sha512';

/**
 * @typedef {object} PassphraseOptions
 * @property {number}                             [iterations=210000] PBKDF2 iterations. Higher = safer + slower.
 * @property {'sha256' | 'sha384' | 'sha512'}     [kdf='sha512']      Underlying PBKDF2 hash.
 * @property {'hex' | 'base64url'}                [encoding='base64url'] Token output encoding.
 *
 * The `kdf` + `iterations` used at encryption MUST be supplied again at
 * decryption — they are not embedded in the token to keep it compact.
 * If you customise them, make sure both sides agree.
 */

/**
 * Password-Based Encryption (PBE, RFC 8018) — encrypt `data` with a key
 * derived from `passphrase` via PBKDF2, sealed with AES-256-GCM.
 *
 * Pipeline:
 *   1. Draw 16 random salt bytes.
 *   2. Derive a 256-bit key with PBKDF2-SHA512 (210,000 iterations by default).
 *   3. Encrypt with AES-256-GCM (fresh 96-bit IV, 128-bit auth tag).
 *   4. Return base64url(salt || iv || tag || ciphertext).
 *
 * The passphrase is NOT stored — you must supply it again for decryption.
 * The token is fully self-contained: {@link decryptWithPassphrase} needs
 * only the token + passphrase (plus matching KDF options if customised).
 *
 * **Different from `@exortek/password.hashPassword`.** That's one-way
 * user authentication (Argon2/bcrypt). This is two-way data encryption
 * with a passphrase key. Use this for encrypting backup files, config
 * secrets, envelope-encrypted user data — anywhere a human-typed secret
 * unlocks data.
 *
 * @param {string | Buffer | Uint8Array} data       Plaintext.
 * @param {string | Buffer | Uint8Array} passphrase Encryption passphrase.
 * @param {PassphraseOptions}            [options]
 * @returns {Promise<string>}                       Packed token: `salt || iv || tag || ciphertext`.
 * @throws {CryptoError}                            With code `INVALID_ARGUMENT` /
 *                                                  `UNSUPPORTED_ALGORITHM` on bad inputs.
 *
 * @example
 * const token = await encryptWithPassphrase('secret data', 'my-passphrase')
 * // → 'V1StGXR8Z5jdHi6BmyTQ...'  (self-contained, safe to store / transmit)
 *
 * @example
 * // Higher-cost KDF for high-value secrets:
 * const t = await encryptWithPassphrase(data, pw, { iterations: 600_000 })
 *
 * @see https://www.rfc-editor.org/rfc/rfc8018 — PKCS #5 Password-Based Cryptography Spec v2.1
 */
export async function encryptWithPassphrase(data, passphrase, options) {
  assertBytesOrString(data, 'data');
  assertBytesOrString(passphrase, 'passphrase');
  assertOptionalObject(options, 'options');

  const iterations = options?.iterations ?? DEFAULT_ITERATIONS;
  const kdf = options?.kdf ?? DEFAULT_KDF_DIGEST;
  const encoding = options?.encoding ?? 'base64url';
  if (encoding !== 'hex' && encoding !== 'base64url') {
    throw new CryptoError(ErrorCode.INVALID_ARGUMENT, "encoding must be 'hex' or 'base64url'");
  }

  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = await pbkdf2(passphrase, {
    salt,
    iterations,
    keyLength: 32,
    digest: kdf,
    encoding: 'buffer',
  });

  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(toBuffer(data, 'data')), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([salt, iv, tag, ciphertext]).toString(encoding);
}

/**
 * Reverse of {@link encryptWithPassphrase}. Unpacks the token, re-derives
 * the AES key with PBKDF2 + the embedded salt, and decrypts with
 * AES-256-GCM.
 *
 * The `iterations` and `kdf` MUST match what was used at encryption
 * (defaults: 210,000 iterations, SHA-512). If you passed custom values
 * to {@link encryptWithPassphrase}, pass the same here.
 *
 * @param {string}            token
 * @param {string | Buffer | Uint8Array} passphrase
 * @param {PassphraseOptions} [options]
 * @returns {Promise<Buffer>}                       Plaintext bytes.
 * @throws {CryptoError}   With code:
 *   - `INVALID_ARGUMENT` on bad types / encoding
 *   - `INVALID_CIPHERTEXT` if the token is truncated below the fixed header
 *   - `DECRYPT_FAILED` on wrong passphrase, mismatched KDF options, or tampering
 *
 * @example
 * const plaintext = await decryptWithPassphrase(token, 'my-passphrase')
 * console.log(plaintext.toString('utf8'))
 *
 * @example
 * try {
 *   await decryptWithPassphrase(token, wrongPassphrase)
 * } catch (err) {
 *   if (err.code === 'DECRYPT_FAILED') return console.error('wrong passphrase')
 *   throw err
 * }
 */
export async function decryptWithPassphrase(token, passphrase, options) {
  assertString(token, 'token');
  assertBytesOrString(passphrase, 'passphrase');
  assertOptionalObject(options, 'options');

  const iterations = options?.iterations ?? DEFAULT_ITERATIONS;
  const kdf = options?.kdf ?? DEFAULT_KDF_DIGEST;
  const encoding = options?.encoding ?? 'base64url';
  if (encoding !== 'hex' && encoding !== 'base64url') {
    throw new CryptoError(ErrorCode.INVALID_ARGUMENT, "encoding must be 'hex' or 'base64url'");
  }

  const packed = Buffer.from(token, encoding);
  if (packed.length < HEADER_LENGTH) {
    throw new CryptoError(ErrorCode.INVALID_CIPHERTEXT, 'token is too short to be a valid PBE ciphertext');
  }

  const salt = packed.subarray(0, SALT_LENGTH);
  const iv = packed.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const tag = packed.subarray(SALT_LENGTH + IV_LENGTH, HEADER_LENGTH);
  const ciphertext = packed.subarray(HEADER_LENGTH);

  const key = await pbkdf2(passphrase, {
    salt,
    iterations,
    keyLength: 32,
    digest: kdf,
    encoding: 'buffer',
  });

  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    throw new CryptoError(
      ErrorCode.DECRYPT_FAILED,
      'passphrase decryption failed — wrong passphrase, mismatched KDF options, or tampered token',
      { cause: err },
    );
  }
}
