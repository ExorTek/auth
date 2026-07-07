import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertBytesOrString, assertEncoding, assertOptionalObject, assertPositiveInt } from '../internal/validate.js';
import { toBuffer } from '../internal/bytes.js';

const scryptAsync = promisify(crypto.scrypt);

/**
 * @typedef {object} ScryptOptions
 * @property {string | Buffer | Uint8Array}      salt              Salt bytes. Must be uniformly random
 *                                                                  and unique per password. ≥ 16 bytes recommended.
 * @property {number}                            [keyLength=32]    Output key length in bytes.
 * @property {number}                            [N=32768]         CPU/memory cost parameter (power of 2).
 *                                                                  OWASP 2024 min is 2^15 = 32768.
 *                                                                  2^17 recommended for slow-path (interactive).
 * @property {number}                            [r=8]             Block size parameter.
 * @property {number}                            [p=1]             Parallelisation parameter.
 * @property {number}                            [maxmem]          Optional Node maxmem override (bytes).
 * @property {'hex' | 'base64' | 'base64url' | 'buffer'} [encoding='buffer']
 *                                                                  Output format.
 */

/**
 * scrypt (RFC 7914) memory-hard key derivation from a password / passphrase.
 *
 * Alternative to {@link pbkdf2} when GPU / ASIC resistance matters —
 * scrypt requires memory proportional to `N × r × p × 128 bytes`, forcing
 * attackers to pay for RAM as well as CPU. Slower to compute than PBKDF2
 * at the same wall-clock cost, but harder to accelerate with dedicated
 * hardware.
 *
 * Node's default `maxmem` is 32 MiB; raise it via `options.maxmem` if
 * you need higher `N` for password verification servers.
 *
 * **Not a password hash storage format.** For storing password
 * verifiers use `@exortek/password` (Argon2). scrypt is a KDF primitive
 * — the output is raw key material, not a self-describing hash string.
 *
 * @param {string | Buffer | Uint8Array} password
 * @param {ScryptOptions}                options
 * @returns {Promise<string | Buffer>}   Encoded key (Buffer by default).
 * @throws {CryptoError}   With code `INVALID_ARGUMENT` on bad inputs.
 *
 * @example
 * // Derive a 32-byte AES-256 key from a passphrase:
 * const salt = bytes(16)
 * const key = await scrypt('user passphrase', { salt })
 *
 * @example
 * // Stronger parameters for high-value credentials:
 * const key = await scrypt('secret', {
 *   salt,
 *   N: 2 ** 17,          // 128 MiB memory
 *   maxmem: 256 * 1024 * 1024,
 *   keyLength: 64,
 * })
 *
 * @see https://www.rfc-editor.org/rfc/rfc7914 — scrypt Password-Based KDF
 */
export async function scrypt(password, options) {
  assertBytesOrString(password, 'password');
  assertOptionalObject(options, 'options');
  if (options === undefined || options.salt === undefined) {
    throw new CryptoError(ErrorCode.INVALID_ARGUMENT, 'options.salt is required');
  }
  assertBytesOrString(options.salt, 'options.salt');

  const keyLength = options.keyLength ?? 32;
  assertPositiveInt(keyLength, 'options.keyLength');
  const N = options.N ?? 32768;
  assertPositiveInt(N, 'options.N');
  const r = options.r ?? 8;
  assertPositiveInt(r, 'options.r');
  const p = options.p ?? 1;
  assertPositiveInt(p, 'options.p');

  const encoding = options.encoding ?? 'buffer';
  assertEncoding(encoding, 'options.encoding');

  const scryptOpts = { N, r, p };
  if (options.maxmem !== undefined) {
    assertPositiveInt(options.maxmem, 'options.maxmem');
    scryptOpts.maxmem = options.maxmem;
  }

  let derived;
  try {
    derived = await scryptAsync(
      toBuffer(password, 'password'),
      toBuffer(options.salt, 'options.salt'),
      keyLength,
      scryptOpts,
    );
  } catch (err) {
    // Node throws for out-of-range N/r/p combinations or maxmem exhaustion.
    throw new CryptoError(ErrorCode.INVALID_ARGUMENT, 'scrypt derivation failed', { cause: err });
  }
  return encoding === 'buffer' ? derived : derived.toString(encoding);
}
