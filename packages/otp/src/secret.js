import { randomBytes } from 'node:crypto';
import { OtpError, ErrorCode } from './internal/errors.js';
import * as base32 from './internal/base32.js';
import { isString } from '@exortek/shared/predicates';

/**
 * @typedef {'base32' | 'base32padded' | 'hex' | 'raw'} SecretEncoding
 */

/**
 * @typedef {object} SecretOptions
 * @property {number} [bytes=20]
 *   Number of random bytes to generate. Default matches RFC 4226's
 *   "recommended minimum" — 20 bytes = 160 bits, the size of a
 *   SHA-1 output. Use 32 for SHA-256, 64 for SHA-512.
 * @property {SecretEncoding} [encoding='base32']
 *   How to encode the returned string. Google Authenticator and every
 *   other TOTP app expects `base32` (RFC 4648, no padding).
 */

/**
 * Generate a cryptographically random OTP secret.
 *
 * The default (20 bytes, base32, no padding) is what every mainstream
 * TOTP app understands — the string is what you render in a QR /
 * paste on the enrollment screen.
 *
 * @param {SecretOptions} [options]
 * @returns {string}
 */
export function generateSecret(options = {}) {
  const bytes = options.bytes ?? 20;
  const encoding = options.encoding ?? 'base32';

  if (!Number.isInteger(bytes) || bytes < 16 || bytes > 128) {
    throw new OtpError(
      ErrorCode.INVALID_ARGUMENT,
      `generateSecret: bytes must be an integer in [16, 128]; got ${bytes}. 20 for SHA-1, 32 for SHA-256, 64 for SHA-512.`,
    );
  }

  const buffer = randomBytes(bytes);
  switch (encoding) {
    case 'base32':
      // Google Authenticator + Authy + 1Password strip padding from the
      // enrollment string, so we default to the same.
      return base32.encode(buffer);
    case 'base32padded': {
      // RFC 4648 padding: pad to a multiple of 8 characters with '='.
      const raw = base32.encode(buffer);
      const pad = (8 - (raw.length % 8)) % 8;
      return raw + '='.repeat(pad);
    }
    case 'hex':
      return buffer.toString('hex');
    case 'raw':
      return buffer.toString('binary');
    default:
      throw new OtpError(
        ErrorCode.INVALID_ARGUMENT,
        `generateSecret: unsupported encoding '${encoding}'. Use 'base32' (default), 'base32padded', 'hex', or 'raw'.`,
      );
  }
}

/**
 * Decode any of the accepted secret encodings into a Buffer for HMAC
 * use. Accepts base32 (with or without padding, case-insensitive,
 * spaces stripped — matches how users paste), hex, and raw Buffers /
 * Uint8Arrays. Never trusts the caller — throws on malformed input.
 *
 * **Auto-detection ambiguity.** When `encoding` is omitted, a string is
 * probed as base32 first, then hex. Some strings are valid under BOTH
 * alphabets (e.g. `'abcdef'` — only `a-f`), and auto-detect will read
 * them as base32, producing the wrong key bytes for a caller who meant
 * hex. If you store secrets hex-encoded, pass `encoding: 'hex'` (or
 * `'base32'`) explicitly to remove the guesswork.
 *
 * @param {string | Buffer | Uint8Array} secret
 * @param {{ encoding?: 'base32' | 'hex' }} [options]
 *   Force the input encoding instead of auto-detecting. Recommended
 *   whenever the secret is not a base32 enrollment string.
 * @returns {Buffer}
 */
export function decodeSecret(secret, options = {}) {
  if (Buffer.isBuffer(secret)) {
    return secret;
  }
  if (secret instanceof Uint8Array) {
    return Buffer.from(secret.buffer, secret.byteOffset, secret.byteLength);
  }
  if (!isString(secret) || secret.length === 0) {
    throw new OtpError(ErrorCode.INVALID_SECRET, 'secret must be a non-empty string, Buffer, or Uint8Array');
  }

  // Normalize whitespace and case — users typically paste secrets with
  // spaces every 4 chars (Google Authenticator's display format).
  const cleaned = secret.replace(/\s+/g, '');

  const encoding = options.encoding;
  if (encoding !== undefined && encoding !== 'base32' && encoding !== 'hex') {
    throw new OtpError(
      ErrorCode.INVALID_ARGUMENT,
      `decodeSecret: encoding must be 'base32' or 'hex'; got ${JSON.stringify(encoding)}`,
    );
  }

  // Explicit hex — no auto-detect, so hex secrets that also happen to be
  // valid base32 are decoded correctly.
  if (encoding === 'hex') {
    if (!/^[0-9a-fA-F]+$/.test(cleaned) || cleaned.length % 2 !== 0) {
      throw new OtpError(ErrorCode.INVALID_SECRET, 'secret is not valid hex (expected an even-length [0-9a-f] string)');
    }
    return Buffer.from(cleaned.toLowerCase(), 'hex');
  }

  // Explicit base32, or auto-detect (base32 first). Base32 alphabet:
  // A-Z2-7 (RFC 4648). Padding is optional.
  if (/^[A-Za-z2-7]+=*$/.test(cleaned)) {
    try {
      return base32.decode(cleaned.toUpperCase());
    } catch (err) {
      throw new OtpError(ErrorCode.INVALID_SECRET, 'secret is not valid base32', {
        cause: err,
      });
    }
  }
  if (encoding === 'base32') {
    throw new OtpError(ErrorCode.INVALID_SECRET, 'secret is not valid base32 — check for characters outside A-Z2-7');
  }

  // Hex fallback — sometimes people store the raw HMAC key hex-encoded.
  if (/^[0-9a-fA-F]+$/.test(cleaned) && cleaned.length % 2 === 0) {
    return Buffer.from(cleaned.toLowerCase(), 'hex');
  }

  throw new OtpError(ErrorCode.INVALID_SECRET, 'secret does not look like base32 or hex — check for stray characters');
}
