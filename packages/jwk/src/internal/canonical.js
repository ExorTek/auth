/**
 * RFC 7638 canonical JSON serialisation for JWK thumbprint input.
 *
 * The thumbprint hash is computed over a specific subset of the JWK's
 * members, in lexicographic order, encoded as a minimal JSON object with
 * no whitespace. This module produces that byte string; it does *not*
 * hash — the digest choice lives with the caller (see
 * {@link ../thumbprint.js thumbprint}).
 *
 * Required members per kty (RFC 7638 §3.2, RFC 8037 §2 for OKP):
 *   - EC:  crv, kty, x, y
 *   - RSA: e, kty, n
 *   - oct: k, kty
 *   - OKP: crv, kty, x
 */

import { JwkError, ErrorCode } from './errors.js';

/**
 * The lexicographically-sorted required-member set for each kty.
 * `JSON.stringify` with these keys in this order and no replacer yields
 * the canonical thumbprint input.
 */
export const REQUIRED_MEMBERS = Object.freeze({
  EC: Object.freeze(['crv', 'kty', 'x', 'y']),
  RSA: Object.freeze(['e', 'kty', 'n']),
  oct: Object.freeze(['k', 'kty']),
  OKP: Object.freeze(['crv', 'kty', 'x']),
});

/**
 * Produce the canonical JSON byte string for a JWK, per RFC 7638 §3.2.
 * Members that are absent throw {@link ErrorCode.MISSING_REQUIRED_MEMBER}.
 *
 * @param {object} jwk
 * @returns {Buffer} the UTF-8 bytes to feed the digest
 */
export function canonicalise(jwk) {
  if (jwk == null || typeof jwk !== 'object') {
    throw new JwkError(ErrorCode.INVALID_ARGUMENT, 'canonicalise: expected a JWK object');
  }
  const kty = /** @type {string} */ (jwk.kty);
  const members = REQUIRED_MEMBERS[/** @type {keyof typeof REQUIRED_MEMBERS} */ (kty)];
  if (!members) {
    throw new JwkError(
      ErrorCode.UNSUPPORTED_KTY,
      `canonicalise: unsupported kty ${JSON.stringify(kty)} — expected one of ${Object.keys(REQUIRED_MEMBERS).join(', ')}`,
    );
  }
  /** @type {Record<string, string>} */
  const projection = {};
  for (const name of members) {
    const value = jwk[name];
    if (value === undefined || value === null || typeof value !== 'string') {
      throw new JwkError(
        ErrorCode.MISSING_REQUIRED_MEMBER,
        `canonicalise: ${kty} JWK is missing required string member ${JSON.stringify(name)}`,
      );
    }
    projection[name] = value;
  }
  return Buffer.from(JSON.stringify(projection), 'utf8');
}
