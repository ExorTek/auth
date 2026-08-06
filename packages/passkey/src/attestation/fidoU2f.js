/**
 * "fido-u2f" attestation (WebAuthn L3 §8.6).
 *
 * The legacy U2F wire format re-cast as a WebAuthn attestation
 * statement. Older security keys and some transitional Android
 * authenticators still ship this. Fixed constraints:
 *
 *   - `alg` is implicit ES256 (ECDSA-SHA256). There is no `alg`
 *     field in the attStmt — the credential public key MUST be
 *     ES256 / P-256, and the attestation signature is verified
 *     with the same digest.
 *   - The credential public key inside authData MUST decode to a
 *     COSE EC2 key with `alg = -7`, `crv = P-256`.
 *   - Signed input is the U2F Raw Message layout: the RESERVED
 *     byte 0x00, then rpIdHash, then clientDataHash, then
 *     credentialId, then the credential public key in the classic
 *     ANSI X9.62 uncompressed form (0x04 || x || y, 65 bytes).
 *   - The certificate chain in `x5c` is exactly one certificate
 *     (leaf) per §8.6 step 1. Anything else violates the spec.
 *
 * Reference: WebAuthn L3 §8.6 (FIDO U2F Attestation Statement
 * Format); FIDO U2F Raw Messages §4.3.
 */

import { createVerify, X509Certificate } from 'node:crypto';
import { verifyChain, toCertificates } from '../x509/chain.js';
import { PasskeyError, ErrorCode } from '../errors.js';

/**
 * @param {object} params
 * @param {Map<unknown, unknown>} params.attStmt
 * @param {Uint8Array} params.authDataBytes
 * @param {Uint8Array} params.clientDataHash
 * @param {import('../webauthn/authData.js').AttestedCredentialData} params.attestedCredentialData
 * @param {Array<unknown>} [params.trustAnchors]
 * @returns {{ format: 'fido-u2f', trustPath: 'trust-anchor' | 'no-anchor', certChain: import('node:crypto').X509Certificate[] }}
 */
export function verifyFidoU2f({ attStmt, authDataBytes, clientDataHash, attestedCredentialData, trustAnchors }) {
  if (!(attStmt instanceof Map)) {
    throw new PasskeyError(ErrorCode.ATTESTATION_INVALID, 'fido-u2f attestation: attStmt is not a CBOR map');
  }
  const x5cRaw = attStmt.get('x5c');
  const sig = attStmt.get('sig');

  if (!Array.isArray(x5cRaw) || x5cRaw.length !== 1 || !(x5cRaw[0] instanceof Uint8Array)) {
    throw new PasskeyError(
      ErrorCode.ATTESTATION_INVALID,
      'fido-u2f attestation: x5c must be a single-element array of bytes (§8.6 step 1)',
    );
  }
  if (!(sig instanceof Uint8Array) || sig.byteLength === 0) {
    throw new PasskeyError(ErrorCode.ATTESTATION_INVALID, 'fido-u2f attestation: attStmt.sig missing or empty');
  }

  // Credential key must be ES256 / P-256 — the format has no alg
  // field and the RP MUST verify with SHA-256 (§8.6 step 2).
  const coseKey = attestedCredentialData.credentialPublicKey;
  const kty = coseKey.get(1);
  const alg = coseKey.get(3);
  const crv = coseKey.get(-1);
  const x = coseKey.get(-2);
  const y = coseKey.get(-3);
  if (kty !== 2 || alg !== -7 || crv !== 1) {
    throw new PasskeyError(
      ErrorCode.ATTESTATION_INVALID,
      `fido-u2f attestation: credential public key must be EC2 / ES256 / P-256 (got kty=${kty}, alg=${alg}, crv=${crv})`,
    );
  }
  if (!(x instanceof Uint8Array) || x.byteLength !== 32 || !(y instanceof Uint8Array) || y.byteLength !== 32) {
    throw new PasskeyError(
      ErrorCode.ATTESTATION_INVALID,
      'fido-u2f attestation: credential public key x / y must be 32-byte coordinates',
    );
  }

  // Build the U2F Raw Message: 0x00 || rpIdHash || clientDataHash ||
  // credentialId || publicKeyU2F. rpIdHash is the first 32 bytes of
  // authData. publicKeyU2F is the classic ANSI X9.62 uncompressed
  // point (0x04 || x || y).
  const rpIdHash = authDataBytes.subarray(0, 32);
  const credentialId = attestedCredentialData.credentialId;
  const publicKeyU2F = new Uint8Array(1 + 32 + 32);
  publicKeyU2F[0] = 0x04;
  publicKeyU2F.set(x, 1);
  publicKeyU2F.set(y, 33);

  const signed = new Uint8Array(1 + 32 + 32 + credentialId.byteLength + publicKeyU2F.byteLength);
  let pos = 0;
  signed[pos++] = 0x00;
  signed.set(rpIdHash, pos);
  pos += 32;
  signed.set(clientDataHash, pos);
  pos += 32;
  signed.set(credentialId, pos);
  pos += credentialId.byteLength;
  signed.set(publicKeyU2F, pos);

  const leaf = new X509Certificate(x5cRaw[0]);

  // The leaf must carry an EC public key on P-256 — no other key
  // type is legal for U2F (FIDO U2F Authenticator Specification §5.6).
  // Node exposes `.publicKey.asymmetricKeyType` and, on EC keys,
  // `.publicKey.asymmetricKeyDetails.namedCurve`.
  const details = leaf.publicKey.asymmetricKeyDetails ?? {};
  if (leaf.publicKey.asymmetricKeyType !== 'ec' || details.namedCurve !== 'prime256v1') {
    throw new PasskeyError(
      ErrorCode.ATTESTATION_INVALID,
      `fido-u2f attestation: attestation certificate must carry an EC P-256 public key (got ${leaf.publicKey.asymmetricKeyType} / ${details.namedCurve ?? 'unknown curve'})`,
    );
  }

  const v = createVerify('SHA256');
  v.update(signed);
  const ok = v.verify({ key: leaf.publicKey, dsaEncoding: 'der' }, sig);
  if (!ok) {
    throw new PasskeyError(
      ErrorCode.SIGNATURE_INVALID,
      'fido-u2f attestation: signature does not verify against leaf certificate',
    );
  }

  let trustPath = 'no-anchor';
  if (trustAnchors && trustAnchors.length > 0) {
    try {
      verifyChain({ x5c: [leaf], trustAnchors: toCertificates(trustAnchors) });
      trustPath = 'trust-anchor';
    } catch (err) {
      throw new PasskeyError(ErrorCode.ATTESTATION_TRUST_ANCHOR_MISSING, `fido-u2f attestation: ${err.message}`);
    }
  }

  return { format: 'fido-u2f', trustPath, certChain: [leaf] };
}
