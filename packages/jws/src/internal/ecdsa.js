/**
 * ASN.1 DER ↔ raw R‖S signature conversion for JWS ECDSA algorithms
 * (RFC 7515 §3.4). Wraps the shared implementation so failures surface
 * as typed {@link ErrorCode.INVALID_SIGNATURE}.
 */

import * as se from '@exortek/shared/ecdsa';
import { JwsError, ErrorCode } from './errors.js';

export const EC_COORD_BYTES = se.EC_COORD_BYTES;

/**
 * Convert Node's ASN.1 DER ECDSA signature to raw R‖S per RFC 7515 §3.4.
 *
 * @param {Buffer} der    the DER-encoded SEQUENCE Node produces
 * @param {string} curve  JWK `crv` value — determines the padding length
 * @returns {Buffer}      raw R‖S of length 2 * EC_COORD_BYTES[curve]
 */
export function derToRaw(der, curve) {
  try {
    return se.derToRaw(der, curve);
  } catch (err) {
    throw new JwsError(ErrorCode.INVALID_SIGNATURE, err instanceof Error ? err.message : String(err));
  }
}

/**
 * Convert a raw R‖S signature to the ASN.1 DER form Node verifies.
 *
 * @param {Buffer} raw
 * @param {string} curve
 * @returns {Buffer}
 */
export function rawToDer(raw, curve) {
  try {
    return se.rawToDer(raw, curve);
  } catch (err) {
    throw new JwsError(ErrorCode.INVALID_SIGNATURE, err instanceof Error ? err.message : String(err));
  }
}
