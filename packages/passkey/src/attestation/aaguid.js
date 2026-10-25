/**
 * The FIDO AAGUID certificate extension (OID 1.3.6.1.4.1.45724.1.1.4),
 * shared by the `packed` and `tpm` verifiers: when an attestation leaf
 * certificate carries it, its value MUST equal authData's AAGUID
 * (WebAuthn L3 §8.2, §8.3).
 */

import { findExtension, readTlv, TAG } from '../asn1/der.js';
import { PasskeyError, ErrorCode } from '../errors.js';

const AAGUID_OID = '1.3.6.1.4.1.45724.1.1.4';

/**
 * Extract the AAGUID from the packed attestation leaf certificate,
 * if present. RFC-shaped: extnValue is OCTET STRING wrapping OCTET
 * STRING wrapping the 16-byte AAGUID.
 *
 * @param {Uint8Array} certDer
 * @returns {Uint8Array | null}
 */
export function readCertAaguid(certDer) {
  const outer = findExtension(certDer, AAGUID_OID);
  if (outer === null) {
    return null;
  }
  const inner = readTlv(outer);
  if (inner.tag !== TAG.OCTET_STRING || inner.contents.byteLength !== 16) {
    throw new PasskeyError(
      ErrorCode.ATTESTATION_INVALID,
      'attestation: AAGUID extension is not a 16-byte OCTET STRING',
    );
  }
  return inner.contents;
}
