/**
 * base64url encode (RFC 4648 §5) — no padding, URL/cookie-safe.
 * @param {Buffer | Uint8Array | string} input
 * @returns {string}
 */
export function encodeBase64Url(input) {
  const buf = typeof input === 'string' ? Buffer.from(input) : Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  return buf.toString('base64url');
}

/**
 * base64url decode. Throws on invalid characters.
 * @param {string} input
 * @returns {Buffer}
 */
export function decodeBase64Url(input) {
  if (typeof input !== 'string') {
    throw new TypeError('base64url input must be a string');
  }
  return Buffer.from(input, 'base64url');
}
