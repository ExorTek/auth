/**
 * "none" attestation (WebAuthn L3 §8.7). No attestation statement,
 * no trust chain. The attStmt object MUST be an empty CBOR map
 * (`a0`); anything else violates the spec and is rejected.
 */

import { throwAttestationInvalid } from '../errors.js';

/**
 * @param {object} params
 * @param {Map<unknown, unknown>} params.attStmt
 * @returns {{ format: 'none', trustPath: 'no-anchor' }}
 */
export function verifyNone({ attStmt }) {
  if (!(attStmt instanceof Map)) {
    throwAttestationInvalid('none attestation: attStmt is not a CBOR map');
  }
  if (attStmt.size !== 0) {
    throwAttestationInvalid(`none attestation: attStmt must be empty, got ${attStmt.size} field(s)`);
  }
  return { format: 'none', trustPath: 'no-anchor' };
}
