/**
 * "android-key" attestation (WebAuthn L3 §8.4).
 *
 * Android StrongBox / Keystore attestation. The leaf attestation
 * certificate carries a Google-defined extension at
 * `1.3.6.1.4.1.11129.2.1.17` whose value is a DER-encoded
 * `KeyDescription`:
 *
 *   KeyDescription ::= SEQUENCE {
 *     attestationVersion         INTEGER,
 *     attestationSecurityLevel   ENUMERATED,
 *     keymasterVersion           INTEGER,
 *     keymasterSecurityLevel     ENUMERATED,
 *     attestationChallenge       OCTET STRING,   -- MUST == clientDataHash
 *     uniqueId                   OCTET STRING,
 *     softwareEnforced           AuthorizationList,
 *     hardwareEnforced           AuthorizationList,
 *   }
 *
 * The `AuthorizationList` uses Keymaster tag numbers up to 700+ in
 * context-specific EXPLICIT form; those require high-tag-number DER
 * decoding which this walker deliberately doesn't do. What we DO
 * enforce (and what the spec requires):
 *
 *   1. attStmt = { alg, sig, x5c }
 *   2. sig verifies with the leaf's public key over
 *      `authData || clientDataHash` using the COSE-named algorithm
 *   3. leaf public key byte-equals the credentialPublicKey (SPKI
 *      DER export, canonical byte identity)
 *   4. extension present, `attestationChallenge` field byte-equals
 *      the clientDataHash
 *   5. chain verifies against RP-supplied trust anchors (Google
 *      hardware root in prod)
 *
 * The AuthorizationList security checks (allApplications absent,
 * origin = KM_ORIGIN_GENERATED = 0, purpose includes KM_PURPOSE_SIGN
 * = 2) are documented in the source but not enforced in 1.0.0
 * because reading them requires a DER walker extension for
 * high-tag-number context-specific tags. Follow-up TODO for 1.1.
 */

import { createVerify, verify as verifyRaw, X509Certificate } from 'node:crypto';
import { importCoseKey, algorithmForId } from '../cose/key.js';
import { verifyChain, toCertificates } from '../x509/chain.js';
import { findExtension, readTlv, readChildren, TAG } from '../asn1/der.js';
import { throwAttestationInvalid, throwAttestationTrustAnchorMissing, throwSignatureInvalid } from '../errors.js';

const ANDROID_KEY_OID = '1.3.6.1.4.1.11129.2.1.17';

/**
 * Extract `attestationChallenge` — the 5th element (index 4) of the
 * top-level KeyDescription SEQUENCE.
 *
 * @param {Uint8Array} certDer
 * @returns {Uint8Array}
 */
function readAttestationChallenge(certDer) {
  const raw = findExtension(certDer, ANDROID_KEY_OID);
  if (raw === null) {
    throwAttestationInvalid(`android-key: leaf missing attestation extension (OID ${ANDROID_KEY_OID})`);
  }
  const outer = readTlv(raw);
  if (outer.tag !== TAG.SEQUENCE) {
    throwAttestationInvalid('android-key: KeyDescription extension is not a SEQUENCE');
  }
  const fields = readChildren(outer.contents);
  // Positions 0..7 per KeyDescription. Guard against short inputs.
  if (fields.length < 8) {
    throwAttestationInvalid(`android-key: KeyDescription has ${fields.length} fields, expected at least 8`);
  }
  const challenge = fields[4];
  if (challenge.tag !== TAG.OCTET_STRING) {
    throwAttestationInvalid('android-key: KeyDescription attestationChallenge is not an OCTET STRING');
  }
  return challenge.contents;
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

function spkiDer(keyObject) {
  return keyObject.export({ format: 'der', type: 'spki' });
}

function verifySignature(publicKey, algParams, data, signature) {
  if (algParams.nodeAlgorithm === null) {
    return verifyRaw(null, data, publicKey, signature);
  }
  const opts = { key: publicKey, ...algParams.verifyOptions };
  const v = createVerify(algParams.nodeAlgorithm);
  v.update(data);
  return v.verify(opts, signature);
}

/**
 * @param {object} params
 * @param {Map<unknown, unknown>} params.attStmt
 * @param {Uint8Array} params.authDataBytes
 * @param {Uint8Array} params.clientDataHash
 * @param {import('../webauthn/authData.js').AttestedCredentialData} params.attestedCredentialData
 * @param {Array<unknown>} [params.trustAnchors]
 * @returns {{
 *   format: 'android-key',
 *   trustPath: 'trust-anchor' | 'no-anchor',
 *   certChain: import('node:crypto').X509Certificate[],
 * }}
 */
export function verifyAndroidKey({ attStmt, authDataBytes, clientDataHash, attestedCredentialData, trustAnchors }) {
  if (!(attStmt instanceof Map)) {
    throwAttestationInvalid('android-key: attStmt is not a CBOR map');
  }
  const alg = attStmt.get('alg');
  const sig = attStmt.get('sig');
  const x5cRaw = attStmt.get('x5c');
  if (typeof alg !== 'number') {
    throwAttestationInvalid('android-key: attStmt.alg missing or not an integer');
  }
  if (!(sig instanceof Uint8Array) || sig.byteLength === 0) {
    throwAttestationInvalid('android-key: attStmt.sig missing or empty');
  }
  if (!Array.isArray(x5cRaw) || x5cRaw.length === 0) {
    throwAttestationInvalid('android-key: attStmt.x5c must be a non-empty array');
  }
  for (const c of x5cRaw) {
    if (!(c instanceof Uint8Array)) {
      throwAttestationInvalid('android-key: attStmt.x5c entries must be byte strings');
    }
  }

  const algParams = algorithmForId(alg);
  const chain = x5cRaw.map(der => new X509Certificate(der));
  const leaf = chain[0];

  // 1. Signature verifies with leaf public key over authData || clientDataHash.
  const signed = new Uint8Array(authDataBytes.byteLength + clientDataHash.byteLength);
  signed.set(authDataBytes, 0);
  signed.set(clientDataHash, authDataBytes.byteLength);
  if (!verifySignature(leaf.publicKey, algParams, signed, sig)) {
    throwSignatureInvalid('android-key: signature does not verify against leaf certificate');
  }

  // 2. Leaf public key MUST byte-equal the credentialPublicKey (SPKI DER).
  const credKey = importCoseKey(attestedCredentialData.credentialPublicKey);
  if (!bytesEqual(new Uint8Array(spkiDer(leaf.publicKey)), new Uint8Array(spkiDer(credKey.publicKey)))) {
    throwAttestationInvalid('android-key: leaf public key does not match credentialPublicKey (SPKI mismatch)');
  }

  // 3. attestationChallenge in the extension MUST equal clientDataHash.
  const challenge = readAttestationChallenge(x5cRaw[0]);
  if (!bytesEqual(challenge, clientDataHash)) {
    throwAttestationInvalid('android-key: attestationChallenge in KeyDescription does not equal clientDataHash');
  }

  // 4. Chain verification.
  let trustPath = 'no-anchor';
  if (trustAnchors && trustAnchors.length > 0) {
    try {
      verifyChain({ x5c: chain, trustAnchors: toCertificates(trustAnchors) });
      trustPath = 'trust-anchor';
    } catch (err) {
      throwAttestationTrustAnchorMissing(`android-key: ${err.message}`);
    }
  }

  return { format: 'android-key', trustPath, certChain: chain };
}
