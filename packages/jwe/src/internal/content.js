/**
 * Content encryption — the JWE `enc` step (RFC 7518 §5). Two AEAD
 * constructions:
 *
 *   - AES-GCM (§5.3) — native AEAD; the tag comes from `getAuthTag()`.
 *   - AES-CBC-HMAC (§5.2) — Encrypt-then-MAC: the CEK splits into a
 *     leading MAC key and a trailing ENC key; the tag is the leftmost
 *     half of HMAC(MAC_KEY, AAD ‖ IV ‖ ciphertext ‖ AL), where AL is the
 *     AAD bit-length as a 64-bit big-endian integer.
 *
 * The Additional Authenticated Data (`aad`) is supplied by the caller —
 * ASCII(Encoded Protected Header) for compact, extended with the JWE AAD
 * for JSON serialization (RFC 7516 §5.1 step 14).
 */

import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { JweError, ErrorCode } from './errors.js';

/** @typedef {import('./encryptions.js').ContentEncryptionDescriptor} EncDescriptor */

/**
 * @typedef {Object} SealedContent
 * @property {Buffer} iv
 * @property {Buffer} ciphertext
 * @property {Buffer} tag
 */

/**
 * Encrypt plaintext under a CEK.
 *
 * @param {EncDescriptor} enc
 * @param {Buffer} cek
 * @param {Buffer} plaintext
 * @param {Buffer} aad
 * @returns {SealedContent}
 */
export function contentEncrypt(enc, cek, plaintext, aad) {
  return enc.kind === 'gcm' ? gcmEncrypt(enc, cek, plaintext, aad) : cbcHmacEncrypt(enc, cek, plaintext, aad);
}

/**
 * Decrypt and authenticate ciphertext under a CEK. Any integrity failure
 * surfaces as {@link ErrorCode.DECRYPTION_FAILED}.
 *
 * @param {EncDescriptor} enc
 * @param {Buffer} cek
 * @param {Buffer} iv
 * @param {Buffer} ciphertext
 * @param {Buffer} tag
 * @param {Buffer} aad
 * @returns {Buffer} The recovered plaintext.
 */
export function contentDecrypt(enc, cek, iv, ciphertext, tag, aad) {
  if (iv.length !== enc.ivBytes) {
    throw new JweError(ErrorCode.DECRYPTION_FAILED, `${enc.enc}: IV must be ${enc.ivBytes} bytes, got ${iv.length}.`);
  }
  if (tag.length !== enc.tagBytes) {
    throw new JweError(
      ErrorCode.DECRYPTION_FAILED,
      `${enc.enc}: authentication tag must be ${enc.tagBytes} bytes, got ${tag.length}.`,
    );
  }
  return enc.kind === 'gcm'
    ? gcmDecrypt(enc, cek, iv, ciphertext, tag, aad)
    : cbcHmacDecrypt(enc, cek, iv, ciphertext, tag, aad);
}

// AES-GCM (RFC 7518 §5.3)

/**
 * @param {EncDescriptor} enc
 * @param {Buffer} cek
 * @param {Buffer} plaintext
 * @param {Buffer} aad
 * @returns {SealedContent}
 */
function gcmEncrypt(enc, cek, plaintext, aad) {
  const iv = randomBytes(enc.ivBytes);
  const cipher = createCipheriv(enc.cipher, cek, iv, { authTagLength: enc.tagBytes });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, ciphertext, tag: cipher.getAuthTag() };
}

/**
 * @param {EncDescriptor} enc
 * @param {Buffer} cek
 * @param {Buffer} iv
 * @param {Buffer} ciphertext
 * @param {Buffer} tag
 * @param {Buffer} aad
 * @returns {Buffer}
 */
function gcmDecrypt(enc, cek, iv, ciphertext, tag, aad) {
  const decipher = createDecipheriv(enc.cipher, cek, iv, { authTagLength: enc.tagBytes });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    throw new JweError(ErrorCode.DECRYPTION_FAILED, `${enc.enc}: AEAD authentication failed.`, { cause: err });
  }
}

// AES-CBC-HMAC (RFC 7518 §5.2)

/**
 * @param {EncDescriptor} enc
 * @param {Buffer} cek
 * @returns {{ macKey: Buffer, encKey: Buffer }}
 */
function splitCek(enc, cek) {
  const half = cek.length / 2;
  return { macKey: cek.subarray(0, half), encKey: cek.subarray(half) };
}

/**
 * The AL value — AAD length in bits as a 64-bit big-endian integer.
 *
 * @param {Buffer} aad
 * @returns {Buffer}
 */
function additionalLength(aad) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(aad.length) * 8n, 0);
  return buf;
}

/**
 * @param {EncDescriptor} enc
 * @param {Buffer} macKey
 * @param {Buffer} aad
 * @param {Buffer} iv
 * @param {Buffer} ciphertext
 * @returns {Buffer}
 */
function computeTag(enc, macKey, aad, iv, ciphertext) {
  const hmac = createHmac(/** @type {string} */ (enc.hash), macKey);
  hmac.update(aad);
  hmac.update(iv);
  hmac.update(ciphertext);
  hmac.update(additionalLength(aad));
  return hmac.digest().subarray(0, enc.tagBytes);
}

/**
 * @param {EncDescriptor} enc
 * @param {Buffer} cek
 * @param {Buffer} plaintext
 * @param {Buffer} aad
 * @returns {SealedContent}
 */
function cbcHmacEncrypt(enc, cek, plaintext, aad) {
  const { macKey, encKey } = splitCek(enc, cek);
  const iv = randomBytes(enc.ivBytes);
  const cipher = createCipheriv(enc.cipher, encKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, ciphertext, tag: computeTag(enc, macKey, aad, iv, ciphertext) };
}

/**
 * @param {EncDescriptor} enc
 * @param {Buffer} cek
 * @param {Buffer} iv
 * @param {Buffer} ciphertext
 * @param {Buffer} tag
 * @param {Buffer} aad
 * @returns {Buffer}
 */
function cbcHmacDecrypt(enc, cek, iv, ciphertext, tag, aad) {
  const { macKey, encKey } = splitCek(enc, cek);
  const expected = computeTag(enc, macKey, aad, iv, ciphertext);
  if (!timingSafeEqual(tag, expected)) {
    throw new JweError(ErrorCode.DECRYPTION_FAILED, `${enc.enc}: HMAC authentication failed.`);
  }
  const decipher = createDecipheriv(enc.cipher, encKey, iv);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    throw new JweError(ErrorCode.DECRYPTION_FAILED, `${enc.enc}: CBC decryption failed.`, { cause: err });
  }
}
