import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertBytesOrString, assertOptionalObject } from '../internal/validate.js';

/**
 * @typedef {'sha256' | 'sha384' | 'sha512' | 'sha1' | 'md5'} HashAlgorithm
 */

/**
 * @typedef {object} HashOptions
 * @property {HashAlgorithm} [algo='sha256']  Digest algorithm. See {@link SUPPORTED_HASHES}.
 * @property {'hex' | 'base64' | 'base64url' | 'buffer'} [encoding='hex']
 *   Output encoding. Use `'hex'` for stored password/token hashes (developer-
 *   friendly, comparable), `'base64url'` for JWT / URL contexts, and
 *   `'buffer'` for raw digest bytes (key derivation, envelope construction,
 *   further chained hashing).
 */

/** Whitelist of supported hash algorithms. */
export const SUPPORTED_HASHES = /** @type {const} */ (['sha256', 'sha384', 'sha512', 'sha1', 'md5']);
const _SUPPORTED = new Set(SUPPORTED_HASHES);

/**
 * Compute a cryptographic hash of `data`.
 *
 * Backed by `node:crypto.createHash`. Default is SHA-256; other algorithms
 * are available via `options.algo` for legacy interop.
 *
 * **Security warning:** `md5` and `sha1` are cryptographically broken —
 * DO NOT use them for password hashing, integrity checks over untrusted
 * inputs, or any collision-resistance dependent use. They are included
 * only for legacy compatibility (checking existing MD5/SHA1 fingerprints).
 *
 * @param {string | Buffer | Uint8Array} data
 * @param {HashOptions}                  [options]
 * @returns {string | Buffer}  Encoded digest (hex string by default);
 *                             `encoding: 'buffer'` returns raw digest bytes.
 * @throws {CryptoError} With code `INVALID_ARGUMENT` if `data` is neither a string nor
 *                       a Buffer, or `UNSUPPORTED_ALGORITHM` if `options.algo` is not
 *                       in {@link SUPPORTED_HASHES}.
 *
 * @example
 * hash('hello world')                     // '...sha256 hex...'
 * hash('hello', { algo: 'sha512' })       // '...sha512 hex...'
 * hash('hello', { encoding: 'base64url' })// '...sha256 base64url...'
 * hash('hello', { encoding: 'buffer' })   // Buffer<...>
 */
export function hash(data, options) {
  assertBytesOrString(data, 'data');
  const { algo, encoding } = _resolveOptions(options);
  const digest = crypto.createHash(algo).update(data);
  return encoding === 'buffer' ? digest.digest() : digest.digest(encoding);
}

/**
 * @private
 * @param {HashOptions} [options]
 * @returns {{ algo: HashAlgorithm, encoding: 'hex' | 'base64' | 'base64url' }}
 */
export function _resolveOptions(options) {
  assertOptionalObject(options, 'options');
  const algo = options?.algo ?? 'sha256';
  if (!_SUPPORTED.has(algo)) {
    throw new CryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `algo must be one of: ${SUPPORTED_HASHES.join(', ')}`,
    );
  }
  const encoding = options?.encoding ?? 'hex';
  if (encoding !== 'hex' && encoding !== 'base64' && encoding !== 'base64url' && encoding !== 'buffer') {
    throw new CryptoError(
      ErrorCode.INVALID_ARGUMENT,
      "encoding must be 'hex', 'base64', 'base64url', or 'buffer'",
    );
  }
  return { algo, encoding };
}
