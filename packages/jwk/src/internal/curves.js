/**
 * Curve name mappings between JWK (`crv` member per RFC 7518 §6.2 and
 * RFC 8037 §2) and Node's `node:crypto` naming.
 *
 * EC curves (RFC 7518 §6.2.1.1) — "P-256", "P-384", "P-521".
 * OKP curves (RFC 8037 §2) — "Ed25519", "Ed448", "X25519", "X448".
 * The `secp256k1` curve is registered for JOSE by RFC 8812 (JWK crv value
 * "secp256k1", JWS alg "ES256K") and is included for Web3 / Bitcoin use
 * cases.
 *
 * These tables are pure data — no logic. They translate between two
 * naming worlds so callers never have to guess which spelling wins.
 */

/**
 * JWK `crv` → Node `namedCurve` for EC keys.
 * Node accepts either the RFC-friendly names (`prime256v1`) or the JWK
 * names (`P-256`) via {@link node:crypto.generateKeyPair}, but our own
 * generate/import path normalises through this table.
 */
export const EC_CURVES = Object.freeze({
  'P-256': 'prime256v1',
  'P-384': 'secp384r1',
  'P-521': 'secp521r1',
  secp256k1: 'secp256k1',
});

/** Inverse of {@link EC_CURVES}: Node curve → JWK `crv`. */
export const EC_CURVES_INVERSE = Object.freeze(
  Object.fromEntries(Object.entries(EC_CURVES).map(([jwk, node]) => [node, jwk])),
);

/**
 * OKP curves recognised by RFC 8037.
 * Node's `generateKeyPair('ed25519' | 'ed448' | 'x25519' | 'x448')`
 * uses lowercase; JWK uses the canonical mixed case shown here.
 */
export const OKP_CURVES = Object.freeze({
  Ed25519: 'ed25519',
  Ed448: 'ed448',
  X25519: 'x25519',
  X448: 'x448',
});

/** Inverse of {@link OKP_CURVES}: Node type → JWK `crv`. */
export const OKP_CURVES_INVERSE = Object.freeze(
  Object.fromEntries(Object.entries(OKP_CURVES).map(([jwk, node]) => [node, jwk])),
);

/**
 * Component byte length for each EC curve — the fixed size that `x`, `y`
 * (and private `d`) must decode to after base64url unpadding. Used by
 * {@link ../validate.js validate} to reject malformed coordinates.
 */
export const EC_COORD_BYTES = Object.freeze({
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
  secp256k1: 32,
});

/**
 * Public-key length for each OKP curve. Ed25519 / X25519 are 32 bytes;
 * Ed448 is 57, X448 is 56.
 */
export const OKP_KEY_BYTES = Object.freeze({
  Ed25519: 32,
  Ed448: 57,
  X25519: 32,
  X448: 56,
});
