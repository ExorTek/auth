/**
 * ASN.1 DER ↔ raw R‖S signature conversion for JWS ECDSA algorithms.
 *
 * Node's `crypto.sign('sha256', data, ecKey)` produces an ASN.1 DER
 * `SEQUENCE { INTEGER r, INTEGER s }`. RFC 7515 §3.4 requires the
 * signature to be the raw big-endian concatenation `R‖S`, each padded
 * to the curve's coordinate size (P-256 → 32 B, P-384 → 48 B,
 * P-521 → 66 B, secp256k1 → 32 B).
 *
 * Scaffold stub; the parser + serialiser land in the "internal utility
 * layer" commit.
 */

import { JwsError, ErrorCode } from './errors.js';

/** Coordinate byte length per JWS curve (matches jwk's EC_COORD_BYTES). */
export const EC_COORD_BYTES = Object.freeze({
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
  secp256k1: 32,
});

/** @param {Buffer} _der @param {string} _curve */
export function derToRaw(_der, _curve) {
  throw new JwsError(ErrorCode.INVALID_SIGNATURE, 'ecdsa.derToRaw: not implemented');
}

/** @param {Buffer} _raw @param {string} _curve */
export function rawToDer(_raw, _curve) {
  throw new JwsError(ErrorCode.INVALID_SIGNATURE, 'ecdsa.rawToDer: not implemented');
}
