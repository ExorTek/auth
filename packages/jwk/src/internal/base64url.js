/**
 * `base64url` codec — RFC 4648 §5. Wraps the shared implementation so
 * failures surface as typed `JwkError` at the JWK boundary. JWK member
 * values that carry raw bytes (`x`, `y`, `d`, `n`, `e`, `k`, and the
 * RSA CRT parameters) are encoded as unpadded base64url; the shared
 * decoder's strict roundtrip check turns malformed input into an error
 * here rather than a wrong-length buffer later.
 */

import * as sb from '@exortek/shared/base64url';
import { JwkError, ErrorCode } from './errors.js';

/**
 * Encode a `Buffer` / `Uint8Array` as unpadded base64url.
 *
 * @param {Buffer | Uint8Array} bytes
 * @returns {string}
 */
export function encode(bytes) {
  try {
    return sb.encode(bytes);
  } catch (err) {
    throw new JwkError(ErrorCode.INVALID_ARGUMENT, err instanceof Error ? err.message : String(err));
  }
}

/**
 * Decode an unpadded base64url string into a `Buffer`.
 * Rejects strings containing padding, whitespace, or non-alphabet chars.
 *
 * @param {string} text
 * @returns {Buffer}
 */
export function decode(text) {
  try {
    return sb.decode(text);
  } catch (err) {
    throw new JwkError(ErrorCode.INVALID_FORMAT, err instanceof Error ? err.message : String(err));
  }
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
