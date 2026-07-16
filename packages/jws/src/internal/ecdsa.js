/**
 * ASN.1 DER ↔ raw R‖S signature conversion for JWS ECDSA algorithms.
 *
 * Node's `crypto.sign('sha256', data, ecKey)` produces an ASN.1 DER
 * `SEQUENCE { INTEGER r, INTEGER s }`. RFC 7515 §3.4 requires the
 * signature to be the raw big-endian concatenation `R‖S`, each padded
 * to the curve's coordinate size:
 *
 *   | Curve       | R  | S  | Total |
 *   | ----------- | -- | -- | ----- |
 *   | P-256       | 32 | 32 | 64    |
 *   | P-384       | 48 | 48 | 96    |
 *   | P-521       | 66 | 66 | 132   |
 *   | secp256k1   | 32 | 32 | 64    |
 *
 * These helpers are the whole reason `verify` can hand JWS signatures
 * to Node without a middleware layer per curve.
 */

import { JwsError, ErrorCode } from './errors.js';

/** Coordinate byte length per JWS curve. */
export const EC_COORD_BYTES = Object.freeze({
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
  secp256k1: 32,
});

/**
 * Convert Node's ASN.1 DER ECDSA signature to raw R‖S per RFC 7515 §3.4.
 *
 * @param {Buffer} der    the DER-encoded SEQUENCE Node produces
 * @param {string} curve  JWK `crv` value — determines the padding length
 * @returns {Buffer}      raw R‖S of length 2 * EC_COORD_BYTES[curve]
 */
export function derToRaw(der, curve) {
  const size = EC_COORD_BYTES[curve];
  if (!size) {
    throw new JwsError(ErrorCode.INVALID_SIGNATURE, `ecdsa.derToRaw: unknown curve ${JSON.stringify(curve)}`);
  }
  if (!Buffer.isBuffer(der) || der.length < 8) {
    throw new JwsError(ErrorCode.INVALID_SIGNATURE, 'ecdsa.derToRaw: DER is truncated');
  }
  let offset = 0;
  if (der[offset++] !== 0x30) {
    throw new JwsError(ErrorCode.INVALID_SIGNATURE, 'ecdsa.derToRaw: expected DER SEQUENCE');
  }
  offset += _skipLength(der, offset);

  // r
  if (der[offset++] !== 0x02) {
    throw new JwsError(ErrorCode.INVALID_SIGNATURE, 'ecdsa.derToRaw: expected INTEGER for r');
  }
  const rLen = der[offset++];
  let r = der.subarray(offset, offset + rLen);
  offset += rLen;

  // s
  if (der[offset++] !== 0x02) {
    throw new JwsError(ErrorCode.INVALID_SIGNATURE, 'ecdsa.derToRaw: expected INTEGER for s');
  }
  const sLen = der[offset++];
  let s = der.subarray(offset, offset + sLen);

  // Strip a single leading 0x00 padding byte inserted by DER to keep the
  // signed integer non-negative when the MSB would otherwise be set.
  if (r.length > 0 && r[0] === 0x00) {
    r = r.subarray(1);
  }
  if (s.length > 0 && s[0] === 0x00) {
    s = s.subarray(1);
  }

  if (r.length > size || s.length > size) {
    throw new JwsError(ErrorCode.INVALID_SIGNATURE, `ecdsa.derToRaw: r/s exceed ${size} bytes for ${curve}`);
  }

  const out = Buffer.alloc(size * 2);
  r.copy(out, size - r.length);
  s.copy(out, size * 2 - s.length);
  return out;
}

/**
 * Convert raw R‖S per RFC 7515 §3.4 to Node's ASN.1 DER SEQUENCE form.
 *
 * @param {Buffer} raw    concatenated R‖S, each padded to EC_COORD_BYTES[curve]
 * @param {string} curve  JWK `crv` value
 * @returns {Buffer}      DER-encoded SEQUENCE Node's verifier accepts
 */
export function rawToDer(raw, curve) {
  const size = EC_COORD_BYTES[curve];
  if (!size) {
    throw new JwsError(ErrorCode.INVALID_SIGNATURE, `ecdsa.rawToDer: unknown curve ${JSON.stringify(curve)}`);
  }
  if (!Buffer.isBuffer(raw) || raw.length !== size * 2) {
    throw new JwsError(
      ErrorCode.INVALID_SIGNATURE,
      `ecdsa.rawToDer: expected ${size * 2} bytes for ${curve}, got ${raw ? raw.length : 'null'}`,
    );
  }
  const rEnc = _asn1Integer(raw.subarray(0, size));
  const sEnc = _asn1Integer(raw.subarray(size));
  const body = Buffer.concat([rEnc, sEnc]);
  return Buffer.concat([Buffer.from([0x30]), _asn1Length(body.length), body]);
}

/**
 * @param {Buffer} buf
 * @param {number} offset
 * @returns {number} number of bytes consumed by the length field
 */
function _skipLength(buf, offset) {
  const first = buf[offset];
  if ((first & 0x80) === 0) {
    return 1;
  }
  return 1 + (first & 0x7f);
}

/** Encode a positive big-endian integer as a DER INTEGER TLV. */
function _asn1Integer(bytes) {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0x00) {
    start++;
  }
  let content = bytes.subarray(start);
  if (content[0] & 0x80) {
    content = Buffer.concat([Buffer.from([0x00]), content]);
  }
  return Buffer.concat([Buffer.from([0x02]), _asn1Length(content.length), content]);
}

/** Encode a length in DER's variable-length form. */
function _asn1Length(len) {
  if (len < 0x80) {
    return Buffer.from([len]);
  }
  const bytes = [];
  let x = len;
  while (x > 0) {
    bytes.unshift(x & 0xff);
    x >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
