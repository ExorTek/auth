import { BaseError } from '@exortek/shared/errors';

/**
 * Stable error codes thrown by `@exortek/crypto`.
 *
 * Consumers should branch on `error.code` (not on the human-readable
 * message, which may change). New codes may be added in minor releases;
 * existing codes are kept stable.
 *
 * @readonly
 * @enum {string}
 */
export const ErrorCode = Object.freeze({
  /** A function argument failed type or range validation. */
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  /** Algorithm name is not in the supported whitelist. */
  UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM',
  /** Key material is missing, wrong type, or unusable with the requested algorithm. */
  INVALID_KEY: 'INVALID_KEY',
  /** Ciphertext payload is malformed (truncated, bad framing, wrong encoding). */
  INVALID_CIPHERTEXT: 'INVALID_CIPHERTEXT',
  /** Authenticated decryption failed (auth tag mismatch, tampering, or wrong key). */
  DECRYPT_FAILED: 'DECRYPT_FAILED',
  /** Encoded input is not valid for the requested format (e.g. non-hex chars in hex.decode). */
  INVALID_ENCODING: 'INVALID_ENCODING',
  /** A sealed token's structure/framing is unparseable (bad length, wrong version byte). */
  TOKEN_MALFORMED: 'TOKEN_MALFORMED',
  /** A sealed token failed authenticated decryption (wrong secret, tampered bytes). */
  TOKEN_TAMPERED: 'TOKEN_TAMPERED',
  /** A sealed token's expiry timestamp has passed. */
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
});

/**
 * Error type raised by every public `@exortek/crypto` API on failure.
 *
 * Carries a stable `code` (see {@link ErrorCode}) for programmatic handling
 * and an optional `cause` chain for diagnostics. HTTP status mapping is
 * intentionally NOT included — this library is framework-agnostic; the
 * consuming application decides how to surface errors. (`BaseError`
 * attaches no `status` when the subclass declares no `statuses`.)
 *
 * @example
 * try {
 *   await cipher.decrypt(blob, key, { iv, tag });
 * } catch (err) {
 *   if (err instanceof CryptoError && err.code === ErrorCode.DECRYPT_FAILED) {
 *     // tampered or wrong key
 *   }
 * }
 */
export class CryptoError extends BaseError {}
