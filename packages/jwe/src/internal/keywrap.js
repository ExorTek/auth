/**
 * AES Key Wrap — RFC 3394, the `A128KW` / `A256KW` key-management
 * algorithms and the CEK-wrap step of `ECDH-ES+A128KW` / `+A256KW`
 * (RFC 7518 §4.4 / §4.6). Node exposes this as the `aes<bits>-wrap`
 * ciphers keyed by the KEK, with the RFC 3394 default initial value
 * (eight `0xA6` octets) as the IV.
 */

import { createCipheriv, createDecipheriv } from 'node:crypto';
import { JweError, ErrorCode } from './errors.js';

/** RFC 3394 §2.2.3.1 default IV — the "A6A6A6A6A6A6A6A6" initial value. */
const DEFAULT_IV = Buffer.alloc(8, 0xa6);

/**
 * Wrap a CEK under a key-encryption key.
 *
 * @param {Buffer} kek  16- or 32-byte key-encryption key.
 * @param {Buffer} cek  The content-encryption key to wrap.
 * @returns {Buffer} The wrapped key (CEK length + 8 bytes).
 */
export function aesKeyWrap(kek, cek) {
  const cipher = createCipheriv(`aes${kek.length * 8}-wrap`, kek, DEFAULT_IV);
  return Buffer.concat([cipher.update(cek), cipher.final()]);
}

/**
 * Unwrap a CEK under a key-encryption key. A failed integrity check
 * surfaces as {@link ErrorCode.DECRYPTION_FAILED}.
 *
 * @param {Buffer} kek  16- or 32-byte key-encryption key.
 * @param {Buffer} wrapped  The wrapped key from the JWE Encrypted Key segment.
 * @returns {Buffer} The unwrapped CEK.
 */
export function aesKeyUnwrap(kek, wrapped) {
  try {
    const decipher = createDecipheriv(`aes${kek.length * 8}-wrap`, kek, DEFAULT_IV);
    return Buffer.concat([decipher.update(wrapped), decipher.final()]);
  } catch (err) {
    throw new JweError(
      ErrorCode.DECRYPTION_FAILED,
      'AES key unwrap failed — wrong key-encryption key or a corrupted encrypted-key segment.',
      { cause: err },
    );
  }
}
