/**
 * Key-management algorithm registry — the JWE `alg` header parameter
 * (RFC 7516 §4.1, RFC 7518 §4). This file curates the supported table
 * and translates lookup failures into typed `JweError`s; the actual
 * wrap / unwrap logic (RSA-OAEP, AES-KW, ECDH-ES + Concat KDF, dir)
 * lands in the sibling `keywrap.js` / `ecdh.js` modules.
 *
 *   - RSA-OAEP  (§4.3) — RSA-OAEP · RSA-OAEP-256
 *   - AES-KW    (§4.4) — A128KW · A256KW
 *   - ECDH-ES   (§4.6) — ECDH-ES · ECDH-ES+A128KW · ECDH-ES+A256KW
 *   - Direct    (§4.5) — dir
 *
 * `RSA1_5` is deliberately **not** in the table — RFC 8017 §7.2 padding
 * oracle, and draft-ietf-jose-deprecate-none-rsa15 removes it outright.
 * `lookup('RSA1_5')` throws {@link ErrorCode.UNSUPPORTED_ALGORITHM}, the
 * same posture `@exortek/jws` takes toward `alg: 'none'`.
 */

import { JweError, ErrorCode } from './errors.js';

/**
 * @typedef {Object} KeyManagementDescriptor
 * @property {string} alg  The JOSE `alg` identifier.
 * @property {'rsa' | 'aeskw' | 'ecdh' | 'dir'} kind  Wrap family.
 * @property {'sha1' | 'sha256'} [hash]  OAEP hash (RSA family only).
 * @property {number} [bits]  AES key-wrap KEK size in bits (AES-KW only).
 * @property {'A128KW' | 'A256KW' | null} [wrap]  CEK wrap step for ECDH-ES
 *   (`null` = ECDH-ES direct, the derived secret *is* the CEK).
 */

/** @type {Record<string, KeyManagementDescriptor>} */
const KEY_MANAGEMENT = {
  'RSA-OAEP': { alg: 'RSA-OAEP', kind: 'rsa', hash: 'sha1' },
  'RSA-OAEP-256': { alg: 'RSA-OAEP-256', kind: 'rsa', hash: 'sha256' },

  A128KW: { alg: 'A128KW', kind: 'aeskw', bits: 128 },
  A256KW: { alg: 'A256KW', kind: 'aeskw', bits: 256 },

  'ECDH-ES': { alg: 'ECDH-ES', kind: 'ecdh', wrap: null },
  'ECDH-ES+A128KW': { alg: 'ECDH-ES+A128KW', kind: 'ecdh', wrap: 'A128KW' },
  'ECDH-ES+A256KW': { alg: 'ECDH-ES+A256KW', kind: 'ecdh', wrap: 'A256KW' },

  dir: { alg: 'dir', kind: 'dir' },
};

/** Every JWE `alg` identifier this package supports. */
export const SUPPORTED = Object.freeze(Object.keys(KEY_MANAGEMENT));

/**
 * Look up a key-management descriptor. Throws
 * {@link ErrorCode.UNSUPPORTED_ALGORITHM} for anything not in the table,
 * including the deliberately-excluded `RSA1_5`.
 *
 * @param {string} alg
 * @returns {KeyManagementDescriptor}
 */
export function lookup(alg) {
  const descriptor = KEY_MANAGEMENT[alg];
  if (descriptor === undefined) {
    throw new JweError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `JWE "alg" ${JSON.stringify(alg)} is not supported. Expected one of: ${SUPPORTED.join(', ')}. Note: RSA1_5 is intentionally unsupported (padding-oracle weakness).`,
    );
  }
  return descriptor;
}
