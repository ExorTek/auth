/**
 * @typedef {'aes-256-gcm' | 'chacha20-poly1305' | 'aes-256-cbc'} SymmetricAlgorithm
 * @typedef {'rsa-oaep' | 'rsa-oaep-256'} AsymmetricAlgorithm
 * @typedef {'ecdh-p256' | 'ecdh-p384' | 'x25519'} KeyAgreementAlgorithm
 */

/**
 * Registry of supported symmetric algorithms.
 *
 * `mode: 'aead'` produces an authentication tag alongside the ciphertext
 * (returned as `tag` and required for decryption). `mode: 'cbc'` produces
 * no tag — use it only when interoperating with legacy systems; prefer
 * `aes-256-gcm` for new code.
 */
export const SYMMETRIC = Object.freeze(
  /** @type {Record<SymmetricAlgorithm, { keyLength: number, ivLength: number, tagLength: number, mode: 'aead' | 'cbc' }>} */ ({
    'aes-256-gcm': { keyLength: 32, ivLength: 12, tagLength: 16, mode: 'aead' },
    'chacha20-poly1305': { keyLength: 32, ivLength: 12, tagLength: 16, mode: 'aead' },
    'aes-256-cbc': { keyLength: 32, ivLength: 16, tagLength: 0, mode: 'cbc' },
  }),
);

/**
 * Registry of supported RSA-OAEP variants. `hash` is the OAEP hash function.
 * Modulus length is 2048 bits — 128-bit security level. Larger keys
 * (`generateKeyPair` accepts an override) work identically for
 * `encrypt` / `decrypt` since the algorithm parameters are read from
 * the KeyObject.
 */
export const ASYMMETRIC = Object.freeze(
  /** @type {Record<AsymmetricAlgorithm, { modulusLength: number, hash: string }>} */ ({
    'rsa-oaep': { modulusLength: 2048, hash: 'sha1' },
    'rsa-oaep-256': { modulusLength: 2048, hash: 'sha256' },
  }),
);

/**
 * Registry of key-agreement (ECDH / X25519) curves.
 *
 * `x25519` is the modern default — faster than P-256 and P-384, with a
 * fixed curve and no small-subgroup attacks. P-256 and P-384 are provided
 * for interoperability with systems that mandate NIST curves.
 */
export const KEY_AGREEMENT = Object.freeze(
  /** @type {Record<KeyAgreementAlgorithm, { type: 'ec' | 'x25519', namedCurve?: string }>} */ ({
    'ecdh-p256': { type: 'ec', namedCurve: 'prime256v1' },
    'ecdh-p384': { type: 'ec', namedCurve: 'secp384r1' },
    x25519: { type: 'x25519' },
  }),
);

export const SYMMETRIC_ALGOS = /** @type {SymmetricAlgorithm[]} */ (Object.keys(SYMMETRIC));
export const ASYMMETRIC_ALGOS = /** @type {AsymmetricAlgorithm[]} */ (Object.keys(ASYMMETRIC));
export const KEY_AGREEMENT_ALGOS = /** @type {KeyAgreementAlgorithm[]} */ (Object.keys(KEY_AGREEMENT));
