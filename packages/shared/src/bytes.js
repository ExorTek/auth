/**
 * String / Buffer / Uint8Array → Buffer coercion — the single
 * implementation behind every `@exortek/*` package's input-coercion
 * helper. Strings default to UTF-8; the encoding-aware variant lets
 * verify paths decode an already-encoded blob back to bytes.
 *
 * Errors are plain `Error` — consumers wrap into their typed error
 * class at the surface, same convention as every other shared module.
 */

/**
 * Coerce `value` into a `Buffer`, decoding strings as UTF-8.
 *
 * - Strings → `Buffer.from(value, 'utf8')`.
 * - `Buffer` → passed through (identity, no copy).
 * - `Uint8Array` → wrapped without copying the underlying storage.
 *
 * @param {unknown} value
 * @param {string}  name  Argument label for the error message.
 * @returns {Buffer}
 * @throws {Error} on any other shape.
 */
export function toBuffer(value, name) {
  if (typeof value === 'string') {
    return Buffer.from(value, 'utf8');
  }
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new Error(`${name} must be a string or Buffer`);
}

/**
 * Coerce `value` into a `Buffer`, decoding strings with the given
 * encoding instead of UTF-8. Used on the receive side of a signature /
 * digest / token verify.
 *
 * @param {unknown} value
 * @param {string}  name
 * @param {'hex' | 'base64' | 'base64url'} encoding
 * @returns {Buffer}
 * @throws {Error} on any other shape.
 */
export function toBufferWithEncoding(value, name, encoding) {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  if (typeof value === 'string') {
    return Buffer.from(value, encoding);
  }
  throw new Error(`${name} must be a string or Buffer`);
}
