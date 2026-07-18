/**
 * RFC 4648 §5 base64url codec.
 *
 * Node's `Buffer.from(str, 'base64url')` is lenient: it accepts
 * padding, `+`, `/`, and whitespace. Wire-level use (JOSE compact
 * serialisation, JWK ingest, etc.) requires strict rejection of
 * everything that isn't a canonical unpadded encoding — hence the
 * roundtrip check in `decode`.
 *
 * Throws plain `Error` / `TypeError` on malformed input. Callers that
 * need typed errors wrap the call at their surface boundary.
 */

const ALPHABET = /^[A-Za-z0-9_-]*$/;

/**
 * @param {Buffer | Uint8Array} bytes
 * @returns {string}
 */
export function encode(bytes) {
  if (bytes == null || (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array))) {
    throw new TypeError('base64url.encode: expected Buffer or Uint8Array');
  }
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64url');
}

/**
 * @param {string} text
 * @returns {string}
 */
export function encodeString(text) {
  if (typeof text !== 'string') {
    throw new TypeError('base64url.encodeString: expected a string');
  }
  return Buffer.from(text, 'utf8').toString('base64url');
}

/**
 * @param {unknown} value
 * @returns {string}
 */
export function encodeJson(value) {
  return encodeString(JSON.stringify(value));
}

/**
 * @param {string} text
 * @returns {Buffer}
 */
export function decode(text) {
  if (typeof text !== 'string') {
    throw new TypeError('base64url.decode: expected a string');
  }
  if (!ALPHABET.test(text)) {
    throw new Error('base64url.decode: input contains characters outside the RFC 4648 §5 alphabet');
  }
  const bytes = Buffer.from(text, 'base64url');
  if (bytes.toString('base64url') !== text) {
    throw new Error('base64url.decode: input is not a canonical encoding');
  }
  return bytes;
}

/**
 * @param {string} text
 * @returns {string}
 */
export function decodeToString(text) {
  return decode(text).toString('utf8');
}

/**
 * @param {string} text
 * @returns {unknown}
 */
export function decodeJson(text) {
  return JSON.parse(decodeToString(text));
}
