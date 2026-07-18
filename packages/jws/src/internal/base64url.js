/**
 * `base64url` codec — RFC 4648 §5. Wraps the shared implementation so
 * failures surface as typed `JwsError` for the package's public API.
 */

import * as sb from '@exortek/shared/base64url';
import { JwsError, ErrorCode } from './errors.js';

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
    throw new JwsError(ErrorCode.INVALID_ARGUMENT, err instanceof Error ? err.message : String(err));
  }
}

/**
 * Encode a UTF-8 string as unpadded base64url.
 *
 * @param {string} text
 * @returns {string}
 */
export function encodeString(text) {
  try {
    return sb.encodeString(text);
  } catch (err) {
    throw new JwsError(ErrorCode.INVALID_ARGUMENT, err instanceof Error ? err.message : String(err));
  }
}

/**
 * Encode a JSON-serialisable value as unpadded base64url of its
 * UTF-8 JSON representation.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function encodeJson(value) {
  return sb.encodeJson(value);
}

/**
 * Decode an unpadded base64url string into a `Buffer`. Rejects strings
 * containing padding, whitespace, or non-alphabet characters, and
 * rejects non-canonical encodings via a roundtrip check.
 *
 * @param {string} text
 * @returns {Buffer}
 */
export function decode(text) {
  try {
    return sb.decode(text);
  } catch (err) {
    throw new JwsError(ErrorCode.INVALID_TOKEN, err instanceof Error ? err.message : String(err));
  }
}

/**
 * Decode base64url and interpret the result as UTF-8.
 *
 * @param {string} text
 * @returns {string}
 */
export function decodeString(text) {
  return decode(text).toString('utf8');
}

/**
 * Decode base64url and parse the result as JSON. Errors are tagged by
 * context so the caller (`verify` for the header, JSON serialisation for
 * the payload) gets the right error code.
 *
 * @param {string} text
 * @param {'header' | 'payload'} [context='header']
 * @returns {unknown}
 */
export function decodeJson(text, context = 'header') {
  const raw = decodeString(text);
  try {
    return JSON.parse(raw);
  } catch (err) {
    throw new JwsError(
      context === 'header' ? ErrorCode.INVALID_HEADER : ErrorCode.INVALID_PAYLOAD,
      `base64url.decodeJson (${context}): value is not valid JSON — ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    );
  }
}
