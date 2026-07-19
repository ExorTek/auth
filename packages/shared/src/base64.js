/**
 * RFC 4648 §4 base64 codec.
 *
 * The **default** shape is unpadded — the trailing `=` characters Node
 * emits are stripped. PHC-format hash strings (argon2 / scrypt /
 * pbkdf2 output) require this shape, and paseto / opaque tokens will
 * too. Pass `{ pad: true }` when interop with a picky RFC 4648-strict
 * reader is needed (very few in practice — Node, Python's `base64.b64decode`,
 * browser `atob`, and every mainstream base64 reader accepts both).
 *
 * `decode` uses Node's tolerant base64 reader, which accepts unpadded,
 * padded, or partially-padded input — matching how most callers hand
 * PHC strings in.
 *
 * Note: this is the **URL-unsafe** alphabet (`+` and `/`). URL-safe
 * base64 (`-` and `_`) lives in `@exortek/shared/base64url` and applies
 * a stricter canonical-roundtrip check that PHC deliberately does not.
 */

/**
 * @param {Buffer | Uint8Array} bytes
 * @param {{ pad?: boolean }} [options]
 *   `pad: true` → keep the trailing `=` padding.
 *   Default (`pad: false` / omitted) → strip padding.
 * @returns {string}
 */
export function encode(bytes, options) {
  const raw = Buffer.from(bytes).toString('base64');
  return options?.pad === true ? raw : raw.replace(/=+$/, '');
}

/**
 * @param {string} s
 * @returns {Buffer}
 */
export function decode(s) {
  return Buffer.from(s, 'base64');
}
