import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertBytesOrString, assertOptionalObject, assertPositiveInt } from '../internal/validate.js';
import { toBuffer } from '../internal/bytes.js';

const pbkdf2Async = promisify(crypto.pbkdf2);

/** Supported PBKDF2 underlying hash functions. */
export const SUPPORTED_PBKDF2_HASHES = /** @type {const} */ (['sha256', 'sha384', 'sha512']);
const _SUPPORTED = new Set(SUPPORTED_PBKDF2_HASHES);

/** OWASP 2023 minimum iteration counts for a password-strength input. */
const OWASP_MIN_ITERATIONS = /** @type {const} */ ({
  sha256: 600_000,
  sha384: 250_000,
  sha512: 210_000,
});

/**
 * @typedef {object} Pbkdf2Options
 * @property {string | Buffer | Uint8Array}      salt                Salt bytes. Should be uniformly
 *                                                                   random and unique per password.
 *                                                                   At least 16 bytes recommended.
 * @property {number}                            [iterations=210000] Number of PBKDF2 iterations.
 *                                                                   Defaults to the OWASP 2023 minimum
 *                                                                   for SHA-512. Higher = slower + safer.
 * @property {number}                            [keyLength=32]      Output key length in bytes.
 *                                                                   `32` matches AES-256 / HMAC-SHA-256.
 * @property {'sha256' | 'sha384' | 'sha512'}    [digest='sha512']   Underlying HMAC hash. SHA-512 is
 *                                                                   marginally faster on 64-bit CPUs
 *                                                                   for the same security level.
 * @property {'hex' | 'base64' | 'base64url' | 'buffer'} [encoding='buffer']
 *                                                                   Output format.
 */

/**
 * PBKDF2 (RFC 8018) key derivation from a password / passphrase.
 *
 * Turns a low-entropy secret (a user passphrase) into high-entropy key
 * material suitable for use with symmetric ciphers, HMAC, JWT signing,
 * session-key derivation, or any place a fixed-size Buffer key is
 * required.
 *
 * The output is deterministic under a fixed `(password, salt, iterations,
 * keyLength, digest)` tuple. You must supply the same tuple later to
 * recover the same key — treat all five as part of the "recipe" and
 * store what you need to reproduce it (usually just the salt).
 *
 * **Not a password hash.** For storing password verifiers use
 * `@exortek/password` (Argon2/bcrypt) — PBKDF2 is fine but Argon2 is
 * memory-hard and better resists GPU attacks.
 *
 * @param {string | Buffer | Uint8Array} password
 * @param {Pbkdf2Options}                options
 * @returns {Promise<string | Buffer>}   Encoded key (Buffer by default).
 * @throws {CryptoError}   With code:
 *   - `INVALID_ARGUMENT` if `password` / `salt` types are wrong,
 *     `iterations` / `keyLength` are not positive integers
 *   - `UNSUPPORTED_ALGORITHM` if `digest` is not one of {@link SUPPORTED_PBKDF2_HASHES}
 *
 * @example
 * // Derive a 32-byte AES-256 key from a passphrase:
 * const salt = bytes(16)
 * const key = await pbkdf2('user passphrase', { salt })
 *
 * @example
 * // Explicit tuning for a specific security posture:
 * const key = await pbkdf2('secret', {
 *   salt,
 *   iterations: 600_000,
 *   keyLength: 64,     // HMAC-SHA-512 key size
 *   digest: 'sha512',
 * })
 */
export async function pbkdf2(password, options) {
  assertBytesOrString(password, 'password');
  assertOptionalObject(options, 'options');
  if (options === undefined || options.salt === undefined) {
    throw new CryptoError(ErrorCode.INVALID_ARGUMENT, 'options.salt is required');
  }
  assertBytesOrString(options.salt, 'options.salt');
  const digest = options.digest ?? 'sha512';
  if (!_SUPPORTED.has(digest)) {
    throw new CryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `digest must be one of: ${SUPPORTED_PBKDF2_HASHES.join(', ')}`,
    );
  }
  const iterations = options.iterations ?? OWASP_MIN_ITERATIONS[digest];
  assertPositiveInt(iterations, 'options.iterations');
  const keyLength = options.keyLength ?? 32;
  assertPositiveInt(keyLength, 'options.keyLength');

  const encoding = options.encoding ?? 'buffer';
  if (encoding !== 'hex' && encoding !== 'base64' && encoding !== 'base64url' && encoding !== 'buffer') {
    throw new CryptoError(ErrorCode.INVALID_ARGUMENT, "encoding must be 'hex', 'base64', 'base64url', or 'buffer'");
  }

  const derived = await pbkdf2Async(
    toBuffer(password, 'password'),
    toBuffer(options.salt, 'options.salt'),
    iterations,
    keyLength,
    digest,
  );
  return encoding === 'buffer' ? derived : derived.toString(encoding);
}
