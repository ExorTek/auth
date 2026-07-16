/**
 * `base64url` codec — RFC 4648 §5.
 *
 * Standalone per package policy: this is deliberately not shared with
 * `@exortek/jwk`'s base64url. Users install this package on its own; no
 * cross-`@exortek` dependency is taken.
 *
 * Node's `Buffer.from(str, 'base64url')` is lenient — accepts padding,
 * `+`, `/`, whitespace. The `decode` helper here roundtrips to reject
 * everything that isn't a canonical unpadded encoding, which is exactly
 * what the JWS spec requires at the token boundary.
 */

import { JwsError, ErrorCode } from './errors.js';

const ALPHABET = /^[A-Za-z0-9_-]*$/;

/**
 * Encode a `Buffer` / `Uint8Array` as unpadded base64url.
 *
 * @param {Buffer | Uint8Array} bytes
 * @returns {string}
 */
export function encode(bytes) {
  if (bytes == null || (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array))) {
    throw new JwsError(ErrorCode.INVALID_ARGUMENT, 'base64url.encode: expected Buffer or Uint8Array');
  }
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64url');
}

/**
 * Encode a UTF-8 string as unpadded base64url.
 *
 * @param {string} text
 * @returns {string}
 */
export function encodeString(text) {
  if (typeof text !== 'string') {
    throw new JwsError(ErrorCode.INVALID_ARGUMENT, 'base64url.encodeString: expected a string');
  }
  return Buffer.from(text, 'utf8').toString('base64url');
}

/**
 * Encode a JSON-serialisable value as unpadded base64url of its
 * UTF-8 JSON representation.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function encodeJson(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
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
  if (typeof text !== 'string') {
    throw new JwsError(ErrorCode.INVALID_TOKEN, 'base64url.decode: expected a string');
  }
  if (!ALPHABET.test(text)) {
    throw new JwsError(
      ErrorCode.INVALID_TOKEN,
      'base64url.decode: input contains characters outside the RFC 4648 §5 alphabet',
    );
  }
  const buf = Buffer.from(text, 'base64url');
  if (buf.toString('base64url') !== text) {
    throw new JwsError(
      ErrorCode.INVALID_TOKEN,
      'base64url.decode: input is not a canonical unpadded base64url encoding',
    );
  }
  return buf;
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
