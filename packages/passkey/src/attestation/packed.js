/**
 * "packed" attestation (WebAuthn L3 §8.2). Two modes:
 *
 *   - "self" (no x5c): the attestation is signed with the newly
 *     minted credential's private key. Signature verifies with the
 *     credentialPublicKey from authData. `alg` MUST match the COSE
 *     algorithm advertised by the credential key.
 *
 *   - "full" (x5c present): the attestation is signed with the
 *     attestation certificate's private key. Signature verifies
 *     with x5c[0]'s public key. The certificate chain must
 *     terminate at an RP-trusted anchor. If the leaf cert carries
 *     the FIDO AAGUID extension (OID 1.3.6.1.4.1.45724.1.1.4), its
 *     value MUST match authData's aaguid.
 *
 * Signed data: `authData || clientDataHash`.
 */

import { createVerify, verify as verifyRaw, X509Certificate } from 'node:crypto';
import { importCoseKey, algorithmForId } from '../cose/key.js';
import { verifyChain, toCertificates } from '../x509/chain.js';
import { findExtension, readTlv, TAG } from '../asn1/der.js';
import { bytesEqual, concat } from '../internal/bytes.js';
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
function readCertAaguid(certDer) {
  const outer = findExtension(certDer, AAGUID_OID);
  if (outer === null) {
    return null;
  }
  const inner = readTlv(outer);
  if (inner.tag !== TAG.OCTET_STRING || inner.contents.byteLength !== 16) {
    throw new PasskeyError(
      ErrorCode.ATTESTATION_INVALID,
      'packed attestation: AAGUID extension is not a 16-byte OCTET STRING',
    );
  }
  return inner.contents;
}

/**
 * @param {object} params
 * @param {Map<unknown, unknown>} params.attStmt
 * @param {Uint8Array} params.authDataBytes  raw authData for signature-input reassembly
 * @param {Uint8Array} params.clientDataHash SHA-256(clientDataJSON)
 * @param {import('../webauthn/authData.js').AttestedCredentialData} params.attestedCredentialData
 * @param {Array<import('node:crypto').X509Certificate>} [params.trustAnchors]
 * @returns {{
 *   format: 'packed',
 *   trustPath: 'self' | 'trust-anchor' | 'no-anchor',
 *   certChain?: import('node:crypto').X509Certificate[],
 *   aaguidExtensionOk?: boolean,
 * }}
 */
export function verifyPacked({ attStmt, authDataBytes, clientDataHash, attestedCredentialData, trustAnchors }) {
  if (!(attStmt instanceof Map)) {
    throw new PasskeyError(ErrorCode.ATTESTATION_INVALID, 'packed attestation: attStmt is not a CBOR map');
  }
  const alg = attStmt.get('alg');
  const sig = attStmt.get('sig');
  const x5cRaw = attStmt.get('x5c');

  if (typeof alg !== 'number') {
    throw new PasskeyError(ErrorCode.ATTESTATION_INVALID, 'packed attestation: attStmt.alg missing or not an integer');
  }
  if (!(sig instanceof Uint8Array) || sig.byteLength === 0) {
    throw new PasskeyError(ErrorCode.ATTESTATION_INVALID, 'packed attestation: attStmt.sig missing or empty');
  }

  const algParams = algorithmForId(alg);
  const signed = concat(authDataBytes, clientDataHash);

  if (x5cRaw === undefined) {
    // Self attestation.
    // alg MUST match credentialPublicKey.alg (WebAuthn L3 §8.2 step 3.1).
    const credAlg = attestedCredentialData.credentialPublicKey.get(3);
    if (credAlg !== alg) {
      throw new PasskeyError(
        ErrorCode.ATTESTATION_INVALID,
        `packed self-attestation: attStmt.alg (${alg}) does not match credentialPublicKey.alg (${credAlg})`,
      );
    }
    const { publicKey } = importCoseKey(attestedCredentialData.credentialPublicKey);
    if (!verifySignature(publicKey, algParams, signed, sig)) {
      throw new PasskeyError(
        ErrorCode.SIGNATURE_INVALID,
        'packed self-attestation: signature does not verify against credential public key',
      );
    }
    return { format: 'packed', trustPath: 'self' };
  }

  // Full attestation with x5c.
  if (!Array.isArray(x5cRaw) || x5cRaw.length === 0) {
    throw new PasskeyError(ErrorCode.ATTESTATION_INVALID, 'packed attestation: attStmt.x5c must be a non-empty array');
  }
  for (const c of x5cRaw) {
    if (!(c instanceof Uint8Array)) {
      throw new PasskeyError(ErrorCode.ATTESTATION_INVALID, 'packed attestation: x5c entries must be byte strings');
    }
  }
  const chain = x5cRaw.map(der => new X509Certificate(der));
  const leaf = chain[0];

  // Signature verifies with the leaf certificate's public key.
  if (!verifySignature(leaf.publicKey, algParams, signed, sig)) {
    throw new PasskeyError(
      ErrorCode.SIGNATURE_INVALID,
      'packed attestation: signature does not verify against leaf certificate',
    );
  }

  // AAGUID extension: if present, must match authData.aaguid.
  const certAaguid = readCertAaguid(x5cRaw[0]);
  let aaguidExtensionOk;
  if (certAaguid !== null) {
    aaguidExtensionOk = bytesEqual(certAaguid, attestedCredentialData.aaguid);
    if (!aaguidExtensionOk) {
      throw new PasskeyError(
        ErrorCode.ATTESTATION_INVALID,
        'packed attestation: cert AAGUID extension does not match authData AAGUID',
      );
    }
  }

  // Basic packed leaf-cert sanity per WebAuthn L3 §8.2 step 2.3:
  //   version=3, subject-OU="Authenticator Attestation", subject-CN/O
  //   present, basicConstraints CA:FALSE.
  // Node exposes .subject as multi-line text; parse loosely to avoid
  // rejecting minor formatting differences.
  const subject = leaf.subject.replace(/\r/g, '');
  if (!/OU=Authenticator Attestation/i.test(subject)) {
    throw new PasskeyError(
      ErrorCode.ATTESTATION_INVALID,
      `packed attestation: leaf subject missing "OU=Authenticator Attestation" per §8.2 step 2.3 (got: ${subject.replace(/\n/g, ' ')})`,
    );
  }
  if (leaf.ca === true) {
    throw new PasskeyError(
      ErrorCode.ATTESTATION_INVALID,
      'packed attestation: leaf basicConstraints CA must be FALSE (§8.2 step 2.3)',
    );
  }

  // Chain verification against RP-supplied anchors.
  let trustPath = 'no-anchor';
  if (trustAnchors && trustAnchors.length > 0) {
    try {
      verifyChain({ x5c: chain, trustAnchors: toCertificates(trustAnchors) });
      trustPath = 'trust-anchor';
    } catch (err) {
      throw new PasskeyError(ErrorCode.ATTESTATION_TRUST_ANCHOR_MISSING, `packed attestation: ${err.message}`);
    }
  }

  return { format: 'packed', trustPath, certChain: chain, aaguidExtensionOk };
}

function verifySignature(publicKey, algParams, data, signature) {
  if (algParams.nodeAlgorithm === null) {
    // Ed25519 / Ed448 — no digest string, verify directly.
    return verifyRaw(null, data, publicKey, signature);
  }
  const opts = { key: publicKey, ...algParams.verifyOptions };
  const v = createVerify(algParams.nodeAlgorithm);
  v.update(data);
  return v.verify(opts, signature);
}
