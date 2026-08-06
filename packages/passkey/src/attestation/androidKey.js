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
 *   5. `allApplications [600]` is absent from both AuthorizationLists
 *      (the key must be RP-scoped, not shared across every app)
 *   6. chain verifies against RP-supplied trust anchors (Google
 *      hardware root in prod)
 *
 * The remaining AuthorizationList fields (origin = KM_ORIGIN_GENERATED
 * = 0, purpose includes KM_PURPOSE_SIGN = 2) are not asserted — matching
 * `@simplewebauthn/server`, which also checks only `allApplications`.
 */

import { createVerify, verify as verifyRaw, X509Certificate } from 'node:crypto';
import { importCoseKey, algorithmForId } from '../cose/key.js';
import { verifyChain, toCertificates } from '../x509/chain.js';
import { findExtension, readTlv, readChildren, TAG } from '../asn1/der.js';
import { bytesEqual, concat } from '../internal/bytes.js';
import { PasskeyError, ErrorCode } from '../errors.js';

const ANDROID_KEY_OID = '1.3.6.1.4.1.11129.2.1.17';

// Keymaster authorization tag: allApplications [600]. A key carrying
// it is usable by *every* app on the device, which defeats the point
// of a per-RP attestation — WebAuthn L3 §8.4 step 4 requires it to be
// absent from both the software- and hardware-enforced lists.
const KM_TAG_ALL_APPLICATIONS = 600;
const CONTEXT_CLASS = 2;

/**
 * Read and structurally validate the KeyDescription SEQUENCE from the
 * leaf's Android Key attestation extension. Returns its top-level
 * child TLVs (indices per WebAuthn L3 §8.4 / Keymaster KeyDescription).
 *
 * @param {Uint8Array} certDer
 * @returns {import('../asn1/der.js').Tlv[]}
 */
function readKeyDescriptionFields(certDer) {
  const raw = findExtension(certDer, ANDROID_KEY_OID);
  if (raw === null) {
    throw new PasskeyError(
      ErrorCode.ATTESTATION_INVALID,
      `android-key: leaf missing attestation extension (OID ${ANDROID_KEY_OID})`,
    );
  }
  const outer = readTlv(raw);
  if (outer.tag !== TAG.SEQUENCE) {
    throw new PasskeyError(ErrorCode.ATTESTATION_INVALID, 'android-key: KeyDescription extension is not a SEQUENCE');
  }
  const fields = readChildren(outer.contents);
  // Positions 0..7 per KeyDescription. Guard against short inputs.
  if (fields.length < 8) {
    throw new PasskeyError(
      ErrorCode.ATTESTATION_INVALID,
      `android-key: KeyDescription has ${fields.length} fields, expected at least 8`,
    );
  }
  return fields;
}

/**
 * Extract `attestationChallenge` — the 5th element (index 4).
 *
 * @param {import('../asn1/der.js').Tlv[]} fields
 * @returns {Uint8Array}
 */
function readAttestationChallenge(fields) {
  const challenge = fields[4];
  if (challenge.tag !== TAG.OCTET_STRING) {
    throw new PasskeyError(
      ErrorCode.ATTESTATION_INVALID,
      'android-key: KeyDescription attestationChallenge is not an OCTET STRING',
    );
  }
  return challenge.contents;
}

/**
 * WebAuthn L3 §8.4 step 4: `allApplications [600]` MUST NOT appear in
 * either the softwareEnforced (index 6) or teeEnforced/hardwareEnforced
 * (index 7) AuthorizationList.
 *
 * @param {import('../asn1/der.js').Tlv[]} fields
 */
function assertNoAllApplications(fields) {
  for (const idx of [6, 7]) {
    const list = fields[idx];
    if (list.tag !== TAG.SEQUENCE) {
      throw new PasskeyError(
        ErrorCode.ATTESTATION_INVALID,
        `android-key: KeyDescription AuthorizationList at index ${idx} is not a SEQUENCE`,
      );
    }
    for (const entry of readChildren(list.contents)) {
      if (entry.tagClass === CONTEXT_CLASS && entry.tagNumber === KM_TAG_ALL_APPLICATIONS) {
        throw new PasskeyError(
          ErrorCode.ATTESTATION_INVALID,
          'android-key: KeyDescription must not contain allApplications [600] — the key is not RP-scoped',
        );
      }
    }
  }
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
    throw new PasskeyError(ErrorCode.ATTESTATION_INVALID, 'android-key: attStmt is not a CBOR map');
  }
  const alg = attStmt.get('alg');
  const sig = attStmt.get('sig');
  const x5cRaw = attStmt.get('x5c');
  if (typeof alg !== 'number') {
    throw new PasskeyError(ErrorCode.ATTESTATION_INVALID, 'android-key: attStmt.alg missing or not an integer');
  }
  if (!(sig instanceof Uint8Array) || sig.byteLength === 0) {
    throw new PasskeyError(ErrorCode.ATTESTATION_INVALID, 'android-key: attStmt.sig missing or empty');
  }
  if (!Array.isArray(x5cRaw) || x5cRaw.length === 0) {
    throw new PasskeyError(ErrorCode.ATTESTATION_INVALID, 'android-key: attStmt.x5c must be a non-empty array');
  }
  for (const c of x5cRaw) {
    if (!(c instanceof Uint8Array)) {
      throw new PasskeyError(ErrorCode.ATTESTATION_INVALID, 'android-key: attStmt.x5c entries must be byte strings');
    }
  }

  const algParams = algorithmForId(alg);
  const chain = x5cRaw.map(der => new X509Certificate(der));
  const leaf = chain[0];

  // 1. Signature verifies with leaf public key over authData || clientDataHash.
  const signed = concat(authDataBytes, clientDataHash);
  if (!verifySignature(leaf.publicKey, algParams, signed, sig)) {
    throw new PasskeyError(
      ErrorCode.SIGNATURE_INVALID,
      'android-key: signature does not verify against leaf certificate',
    );
  }

  // 2. Leaf public key MUST byte-equal the credentialPublicKey (SPKI DER).
  const credKey = importCoseKey(attestedCredentialData.credentialPublicKey);
  if (!bytesEqual(new Uint8Array(spkiDer(leaf.publicKey)), new Uint8Array(spkiDer(credKey.publicKey)))) {
    throw new PasskeyError(
      ErrorCode.ATTESTATION_INVALID,
      'android-key: leaf public key does not match credentialPublicKey (SPKI mismatch)',
    );
  }

  // 3. attestationChallenge in the extension MUST equal clientDataHash,
  //    and allApplications [600] MUST be absent from both auth lists.
  const keyDescription = readKeyDescriptionFields(x5cRaw[0]);
  const challenge = readAttestationChallenge(keyDescription);
  if (!bytesEqual(challenge, clientDataHash)) {
    throw new PasskeyError(
      ErrorCode.ATTESTATION_INVALID,
      'android-key: attestationChallenge in KeyDescription does not equal clientDataHash',
    );
  }
  assertNoAllApplications(keyDescription);

  // 4. Chain verification.
  let trustPath = 'no-anchor';
  if (trustAnchors && trustAnchors.length > 0) {
    try {
      verifyChain({ x5c: chain, trustAnchors: toCertificates(trustAnchors) });
      trustPath = 'trust-anchor';
    } catch (err) {
      throw new PasskeyError(ErrorCode.ATTESTATION_TRUST_ANCHOR_MISSING, `android-key: ${err.message}`);
    }
  }

  return { format: 'android-key', trustPath, certChain: chain };
}
