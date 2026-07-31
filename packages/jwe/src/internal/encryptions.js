/**
 * Content-encryption algorithm registry — the JWE `enc` header parameter
 * (RFC 7516 §4.1, RFC 7518 §5). This file curates the supported table
 * and translates lookup failures into typed `JweError`s; the AEAD
 * encrypt / decrypt logic lands alongside the encryption core.
 *
 *   - AES-GCM       (§5.3) — A128GCM · A192GCM · A256GCM  (Recommended)
 *   - AES-CBC-HMAC  (§5.2) — A128CBC-HS256 · A256CBC-HS512 (Required, interop)
 *
 * The `cek` byte length is what a freshly-generated Content Encryption
 * Key must be; for AES-CBC-HMAC it is the MAC key + ENC key concatenation
 * (RFC 7518 §5.2.2), hence double the raw AES key size.
 */

import { JweError, ErrorCode } from './errors.js';

/**
 * @typedef {Object} ContentEncryptionDescriptor
 * @property {string} enc  The JOSE `enc` identifier.
 * @property {'gcm' | 'cbc-hs'} kind  AEAD construction.
 * @property {number} cekBytes  Total Content Encryption Key length in bytes.
 * @property {number} ivBytes  Initialization Vector length in bytes.
 * @property {number} tagBytes  Authentication Tag length in bytes.
 * @property {string} cipher  node:crypto cipher name for the AES step.
 * @property {'sha256' | 'sha512'} [hash]  HMAC hash (AES-CBC-HMAC only).
 */

/** @type {Record<string, ContentEncryptionDescriptor>} */
const CONTENT_ENCRYPTION = {
  A128GCM: { enc: 'A128GCM', kind: 'gcm', cekBytes: 16, ivBytes: 12, tagBytes: 16, cipher: 'aes-128-gcm' },
  A192GCM: { enc: 'A192GCM', kind: 'gcm', cekBytes: 24, ivBytes: 12, tagBytes: 16, cipher: 'aes-192-gcm' },
  A256GCM: { enc: 'A256GCM', kind: 'gcm', cekBytes: 32, ivBytes: 12, tagBytes: 16, cipher: 'aes-256-gcm' },

  'A128CBC-HS256': {
    enc: 'A128CBC-HS256',
    kind: 'cbc-hs',
    cekBytes: 32,
    ivBytes: 16,
    tagBytes: 16,
    cipher: 'aes-128-cbc',
    hash: 'sha256',
  },
  'A256CBC-HS512': {
    enc: 'A256CBC-HS512',
    kind: 'cbc-hs',
    cekBytes: 64,
    ivBytes: 16,
    tagBytes: 32,
    cipher: 'aes-256-cbc',
    hash: 'sha512',
  },
};

/** Every JWE `enc` identifier this package supports. */
export const SUPPORTED = Object.freeze(Object.keys(CONTENT_ENCRYPTION));

/**
 * Look up a content-encryption descriptor. Throws
 * {@link ErrorCode.UNSUPPORTED_ENCRYPTION} for anything not in the table.
 *
 * @param {string} enc
 * @returns {ContentEncryptionDescriptor}
 */
export function lookup(enc) {
  const descriptor = CONTENT_ENCRYPTION[enc];
  if (descriptor === undefined) {
    throw new JweError(
      ErrorCode.UNSUPPORTED_ENCRYPTION,
      `JWE "enc" ${JSON.stringify(enc)} is not supported. Expected one of: ${SUPPORTED.join(', ')}.`,
    );
  }
  return descriptor;
}
