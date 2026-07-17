/**
 * `base64url` codec — RFC 4648 §5.
 *
 * Standalone per package policy: this is deliberately not shared with
 * `@exortek/jwk` / `@exortek/jws`. Users install this package on its
 * own; no cross-`@exortek` dependency is taken.
 *
 * Node's `Buffer.from(str, 'base64url')` is lenient — accepts padding,
 * `+`, `/`, whitespace. The `decode` helper here roundtrips to reject
 * everything that isn't a canonical unpadded encoding.
 */

import { JwtError, ErrorCode } from './errors.js';

const ALPHABET = /^[A-Za-z0-9_-]*$/;

/**
 * @param {Buffer | Uint8Array} bytes
 * @returns {string}
 */
export function encode(bytes) {
  if (bytes == null || (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array))) {
    throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'base64url.encode: expected Buffer or Uint8Array');
  }
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64url');
}

/**
 * @param {string} text
 * @returns {string}
 */
export function encodeString(text) {
  if (typeof text !== 'string') {
    throw new JwtError(ErrorCode.INVALID_ARGUMENT, 'base64url.encodeString: expected a string');
  }
  return Buffer.from(text, 'utf8').toString('base64url');
}

/**
 * @param {unknown} value
 * @returns {string}
 */
export function encodeJson(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

/**
 * @param {string} text
 * @returns {Buffer}
 */
export function decode(text) {
  if (typeof text !== 'string') {
    throw new JwtError(ErrorCode.INVALID_TOKEN, 'base64url.decode: expected a string');
  }
  if (!ALPHABET.test(text)) {
    throw new JwtError(
      ErrorCode.INVALID_TOKEN,
      'base64url.decode: input contains characters outside the RFC 4648 §5 alphabet',
    );
  }
  const buf = Buffer.from(text, 'base64url');
  if (buf.toString('base64url') !== text) {
    throw new JwtError(
      ErrorCode.INVALID_TOKEN,
      'base64url.decode: input is not a canonical unpadded base64url encoding',
    );
  }
  return buf;
}

/**
 * @param {string} text
 * @returns {string}
 */
export function decodeString(text) {
  return decode(text).toString('utf8');
}

/**
 * @param {string} text
 * @param {'header' | 'payload'} [context='header']
 * @returns {unknown}
 */
export function decodeJson(text, context = 'header') {
  const raw = decodeString(text);
  try {
    return JSON.parse(raw);
  } catch (err) {
    throw new JwtError(
      context === 'header' ? ErrorCode.INVALID_HEADER : ErrorCode.INVALID_PAYLOAD,
      `base64url.decodeJson (${context}): value is not valid JSON — ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    );
  }
}
