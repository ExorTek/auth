/**
 * "apple" attestation (WebAuthn L3 §8.8).
 *
 * Apple's anonymous attestation. Unusual among WebAuthn formats:
 *   - No `sig` in attStmt — trust hangs on Apple's chain plus a
 *     nonce comparison.
 *   - The leaf certificate carries a critical extension at OID
 *     `1.2.840.113635.100.8.2` whose value is a DER SEQUENCE with
 *     a `[1] EXPLICIT OCTET STRING` — the "nonce". That nonce
 *     MUST equal `SHA-256(authData || clientDataHash)`.
 *   - The leaf certificate's public key MUST byte-equal (in the
 *     ANSI X9.62 uncompressed 65-byte form) the credential public
 *     key from `authData`.
 *
 * Reference: WebAuthn L3 §8.8; Apple Anonymous Attestation
 * (Apple Developer docs, WWDC 2020 session 10001).
 */

import { createHash, X509Certificate } from 'node:crypto';
import { verifyChain, toCertificates } from '../x509/chain.js';
import { findExtension, readTlv, readChildren, TAG, contextTag } from '../asn1/der.js';
import { throwAttestationInvalid, throwAttestationTrustAnchorMissing } from '../errors.js';

const APPLE_NONCE_OID = '1.2.840.113635.100.8.2';

/**
 * Extract the Apple anonymous-attestation nonce from a leaf cert.
 * The extension wraps a SEQUENCE whose sole element is
 * `[1] EXPLICIT OCTET STRING` — the nonce bytes.
 *
 * @param {Uint8Array} certDer
 * @returns {Uint8Array}
 */
function readAppleNonce(certDer) {
  const raw = findExtension(certDer, APPLE_NONCE_OID);
  if (raw === null) {
    throwAttestationInvalid('apple attestation: leaf missing nonce extension (OID 1.2.840.113635.100.8.2)');
  }
  const seq = readTlv(raw);
  if (seq.tag !== TAG.SEQUENCE) {
    throwAttestationInvalid('apple attestation: nonce extension is not a SEQUENCE');
  }
  const items = readChildren(seq.contents);
  const tagged = items.find(t => t.tag === contextTag(1));
  if (!tagged) {
    throwAttestationInvalid('apple attestation: nonce extension SEQUENCE missing [1] EXPLICIT OCTET STRING');
  }
  const inner = readTlv(tagged.contents);
  if (inner.tag !== TAG.OCTET_STRING) {
    throwAttestationInvalid('apple attestation: nonce extension inner tag is not OCTET STRING');
  }
  if (inner.contents.byteLength !== 32) {
    throwAttestationInvalid(`apple attestation: nonce must be 32 bytes (got ${inner.contents.byteLength})`);
  }
  return inner.contents;
}

/**
 * Rebuild the ANSI X9.62 uncompressed point (0x04 || x || y) from a
 * COSE EC2 key. Apple attestations MUST use P-256, so we assume
 * 32-byte coordinates.
 *
 * @param {Map<unknown, unknown>} coseKey
 * @returns {Uint8Array}
 */
function coseEc2ToUncompressed(coseKey) {
  if (coseKey.get(1) !== 2 || coseKey.get(-1) !== 1) {
    throwAttestationInvalid('apple attestation: credential key must be EC2 / P-256');
  }
  const x = coseKey.get(-2);
  const y = coseKey.get(-3);
  if (!(x instanceof Uint8Array) || x.byteLength !== 32 || !(y instanceof Uint8Array) || y.byteLength !== 32) {
    throwAttestationInvalid('apple attestation: credential key x / y must be 32-byte Uint8Arrays');
  }
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(x, 1);
  out.set(y, 33);
  return out;
}

/**
 * Extract the leaf certificate's SubjectPublicKeyInfo public key as
 * an uncompressed EC point. Node's `publicKey.export({ format: 'jwk' })`
 * gives us base64url x/y, which we recombine.
 *
 * @param {import('node:crypto').X509Certificate} leaf
 * @returns {Uint8Array}
 */
function leafPublicKeyUncompressed(leaf) {
  if (leaf.publicKey.asymmetricKeyType !== 'ec') {
    throwAttestationInvalid('apple attestation: leaf public key is not EC');
  }
  const details = leaf.publicKey.asymmetricKeyDetails ?? {};
  if (details.namedCurve !== 'prime256v1') {
    throwAttestationInvalid(
      `apple attestation: leaf public key curve must be P-256 (got ${details.namedCurve ?? 'unknown'})`,
    );
  }
  const jwk = leaf.publicKey.export({ format: 'jwk' });
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  if (x.byteLength !== 32 || y.byteLength !== 32) {
    throwAttestationInvalid('apple attestation: leaf EC coordinates are not 32 bytes');
  }
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(x, 1);
  out.set(y, 33);
  return out;
}

function bytesEqual(a, b) {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  for (let i = 0; i < a.byteLength; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/**
 * @param {object} params
 * @param {Map<unknown, unknown>} params.attStmt
 * @param {Uint8Array} params.authDataBytes
 * @param {Uint8Array} params.clientDataHash
 * @param {import('../webauthn/authData.js').AttestedCredentialData} params.attestedCredentialData
 * @param {Array<unknown>} [params.trustAnchors]
 * @returns {{ format: 'apple', trustPath: 'trust-anchor' | 'no-anchor', certChain: import('node:crypto').X509Certificate[] }}
 */
export function verifyApple({ attStmt, authDataBytes, clientDataHash, attestedCredentialData, trustAnchors }) {
  if (!(attStmt instanceof Map)) {
    throwAttestationInvalid('apple attestation: attStmt is not a CBOR map');
  }
  const x5cRaw = attStmt.get('x5c');
  if (!Array.isArray(x5cRaw) || x5cRaw.length === 0) {
    throwAttestationInvalid('apple attestation: x5c must be a non-empty array');
  }
  for (const c of x5cRaw) {
    if (!(c instanceof Uint8Array)) {
      throwAttestationInvalid('apple attestation: x5c entries must be byte strings');
    }
  }
  if (attStmt.has('sig')) {
    throwAttestationInvalid('apple attestation: attStmt must not carry a sig field (§8.8 has no signature)');
  }

  // Nonce check: SHA-256(authData || clientDataHash) must equal the
  // nonce inside the leaf's Apple extension.
  const nonceToHash = new Uint8Array(authDataBytes.byteLength + clientDataHash.byteLength);
  nonceToHash.set(authDataBytes, 0);
  nonceToHash.set(clientDataHash, authDataBytes.byteLength);
  const expectedNonce = new Uint8Array(createHash('sha256').update(nonceToHash).digest());
  const certNonce = readAppleNonce(x5cRaw[0]);
  if (!bytesEqual(expectedNonce, certNonce)) {
    throwAttestationInvalid(
      'apple attestation: nonce in leaf extension does not equal SHA-256(authData || clientDataHash)',
    );
  }

  // Leaf public key MUST byte-equal the credential public key in
  // uncompressed form.
  const chain = x5cRaw.map(der => new X509Certificate(der));
  const leaf = chain[0];
  const leafKey = leafPublicKeyUncompressed(leaf);
  const credKey = coseEc2ToUncompressed(attestedCredentialData.credentialPublicKey);
  if (!bytesEqual(leafKey, credKey)) {
    throwAttestationInvalid('apple attestation: leaf public key does not match credential public key');
  }

  let trustPath = 'no-anchor';
  if (trustAnchors && trustAnchors.length > 0) {
    try {
      verifyChain({ x5c: chain, trustAnchors: toCertificates(trustAnchors) });
      trustPath = 'trust-anchor';
    } catch (err) {
      throwAttestationTrustAnchorMissing(`apple attestation: ${err.message}`);
    }
  }

  return { format: 'apple', trustPath, certChain: chain };
}
