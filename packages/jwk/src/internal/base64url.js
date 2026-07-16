/**
 * `base64url` codec — RFC 4648 §5.
 *
 * All JWK member values that carry raw bytes (`x`, `y`, `d`, `n`, `e`,
 * `k`, and the RSA CRT parameters) are encoded as unpadded base64url.
 * Node's `Buffer.from(str, 'base64url')` and `.toString('base64url')`
 * already strip padding, but Node is *lenient* — it silently accepts
 * padding, `+`, `/`, and even trailing garbage. These helpers add a
 * strict roundtrip check so malformed input turns into an error at the
 * JWK boundary rather than a wrong-length buffer later.
 */

import { JwkError, ErrorCode } from './errors.js';

const ALPHABET = /^[A-Za-z0-9_-]*$/;

/**
 * Encode a `Buffer` / `Uint8Array` as unpadded base64url.
 *
 * @param {Buffer | Uint8Array} bytes
 * @returns {string}
 */
export function encode(bytes) {
  if (bytes == null || (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array))) {
    throw new JwkError(ErrorCode.INVALID_ARGUMENT, 'base64url.encode: expected Buffer or Uint8Array');
  }
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64url');
}

/**
 * Decode an unpadded base64url string into a `Buffer`.
 * Rejects strings containing padding, whitespace, or non-alphabet chars.
 *
 * @param {string} text
 * @returns {Buffer}
 */
export function decode(text) {
  if (typeof text !== 'string') {
    throw new JwkError(ErrorCode.INVALID_FORMAT, 'base64url.decode: expected a string');
  }
  if (!ALPHABET.test(text)) {
    throw new JwkError(
      ErrorCode.INVALID_FORMAT,
      'base64url.decode: input contains characters outside the RFC 4648 §5 alphabet (padding, whitespace, `+`, `/`, or others)',
    );
  }
  const buf = Buffer.from(text, 'base64url');
  // Node's decoder is lenient about trailing partial groups. Round-trip
  // to catch inputs like `A` that decode to zero bytes yet re-encode to ``.
  if (buf.toString('base64url') !== text) {
    throw new JwkError(
      ErrorCode.INVALID_FORMAT,
      'base64url.decode: input is not a canonical unpadded base64url encoding',
    );
  }
  return buf;
}

/**
 * Assert that `text` is a well-formed unpadded base64url string and
 * (optionally) decodes to exactly `expectedBytes` bytes. Errors mention
 * the JWK member name to make validation output actionable.
 *
 * @param {string} text
 * @param {string} memberName which JWK member the value came from
 * @param {number} [expectedBytes]
 * @returns {Buffer}
 */
export function decodeMember(text, memberName, expectedBytes) {
  let buf;
  try {
    buf = decode(text);
  } catch (err) {
    throw new JwkError(ErrorCode.INVALID_JWK, `${memberName}: ${err instanceof Error ? err.message : String(err)}`, {
      cause: err,
    });
  }
  if (expectedBytes != null && buf.length !== expectedBytes) {
    throw new JwkError(
      ErrorCode.INVALID_JWK,
      `${memberName}: expected ${expectedBytes} bytes after base64url decode, got ${buf.length}`,
    );
  }
  return buf;
}
