/**
 * ASN.1 DER ↔ raw R‖S signature conversion for ECDSA. Scaffold stub;
 * the real parser + serialiser land in the utility-layer commit,
 * copied verbatim from `@exortek/jws`.
 */

import { JwtError, ErrorCode } from './errors.js';

/** Coordinate byte length per JWS curve. */
export const EC_COORD_BYTES = Object.freeze({
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
  secp256k1: 32,
});

/** @param {Buffer} _der @param {string} _curve */
export function derToRaw(_der, _curve) {
  throw new JwtError(ErrorCode.INVALID_SIGNATURE, 'ecdsa.derToRaw: not implemented');
}

/** @param {Buffer} _raw @param {string} _curve */
export function rawToDer(_raw, _curve) {
  throw new JwtError(ErrorCode.INVALID_SIGNATURE, 'ecdsa.rawToDer: not implemented');
}
