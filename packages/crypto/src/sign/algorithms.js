import crypto from 'node:crypto';

/**
 * @typedef {'rs256' | 'rs384' | 'rs512'
 *         | 'ps256' | 'ps384' | 'ps512'
 *         | 'es256' | 'es384' | 'es512'
 *         | 'eddsa'} SignAlgorithm
 */

/**
 * Registry of supported asymmetric signature algorithms.
 *
 * Layout:
 * - `type` — Node keygen type family (`'rsa'` | `'ec'` | `'ed25519'`).
 * - `hash` — Message digest algorithm passed to `crypto.sign` / `crypto.verify`.
 *   `null` for Ed25519 (Ed25519 handles hashing internally).
 * - `padding` — RSA padding constant. Undefined for non-RSA.
 * - `modulusLength` / `namedCurve` — key generation parameters.
 *
 * The names follow the IANA JOSE / JWA registry (RS256/PS256/ES256/EdDSA)
 * so that JWT / JWS implementations built on top can pass the header
 * `alg` value straight through.
 */
export const SIGN = Object.freeze(
  /** @type {Record<SignAlgorithm, { type: 'rsa' | 'ec' | 'ed25519', hash: string | null, padding?: number, modulusLength?: number, namedCurve?: string }>} */ ({
    // RSASSA-PKCS1-v1_5
    rs256: { type: 'rsa', hash: 'sha256', padding: crypto.constants.RSA_PKCS1_PADDING, modulusLength: 2048 },
    rs384: { type: 'rsa', hash: 'sha384', padding: crypto.constants.RSA_PKCS1_PADDING, modulusLength: 2048 },
    rs512: { type: 'rsa', hash: 'sha512', padding: crypto.constants.RSA_PKCS1_PADDING, modulusLength: 2048 },
    // RSASSA-PSS
    ps256: { type: 'rsa', hash: 'sha256', padding: crypto.constants.RSA_PKCS1_PSS_PADDING, modulusLength: 2048 },
    ps384: { type: 'rsa', hash: 'sha384', padding: crypto.constants.RSA_PKCS1_PSS_PADDING, modulusLength: 2048 },
    ps512: { type: 'rsa', hash: 'sha512', padding: crypto.constants.RSA_PKCS1_PSS_PADDING, modulusLength: 2048 },
    // ECDSA
    es256: { type: 'ec', hash: 'sha256', namedCurve: 'prime256v1' },
    es384: { type: 'ec', hash: 'sha384', namedCurve: 'secp384r1' },
    es512: { type: 'ec', hash: 'sha512', namedCurve: 'secp521r1' },
    // EdDSA (Ed25519)
    eddsa: { type: 'ed25519', hash: null },
  }),
);

export const SIGN_ALGOS = /** @type {SignAlgorithm[]} */ (Object.keys(SIGN));
