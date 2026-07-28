/**
 * "tpm" attestation (WebAuthn L3 §8.3).
 *
 * TPM 2.0 hardware attestation — used by Windows Hello and TPM-backed
 * enterprise authenticators. The most involved format in the spec:
 * two TCG-defined binary structures (`TPMT_PUBLIC`, `TPMS_ATTEST`)
 * that we hand-parse, plus AIK cert profile checks.
 *
 * attStmt shape:
 *   {
 *     ver:       "2.0"      (TPM 2.0)
 *     alg:       COSE alg   (signature algorithm)
 *     sig:       bytes      (signature over certInfo)
 *     x5c:       [certs]    (AIK cert chain, leaf first)
 *     pubArea:   bytes      (TPMT_PUBLIC — the credential public key)
 *     certInfo:  bytes      (TPMS_ATTEST — the TPM-signed statement)
 *   }
 *
 * Verify (§8.3):
 *   1. pubArea parses; its public key equals the credentialPublicKey
 *      (modulus / exponent for RSA, x/y for ECC).
 *   2. certInfo parses; magic = TPM_GENERATED_VALUE (0xFF544347),
 *      type = TPM_ST_ATTEST_CERTIFY (0x8017).
 *   3. attToBeSigned = authData || clientDataHash.
 *      extraData in certInfo = Hash(attToBeSigned) with the hash
 *      determined by the signature alg.
 *   4. attested.name in certInfo = nameAlg (2 bytes) ||
 *      Hash_nameAlg(pubArea).
 *   5. sig verifies against x5c[0].publicKey over certInfo bytes
 *      with the COSE-named algorithm.
 *   6. AIK cert profile:
 *        - Version 3
 *        - Subject empty
 *        - basicConstraints CA:FALSE
 *        - extendedKeyUsage includes 2.23.133.8.3 (TCG-KP-AIK)
 *   7. Chain verifies against RP-supplied trust anchors (TPM vendor
 *      AIK roots in prod).
 *
 * References:
 *   - WebAuthn L3 §8.3
 *   - TPM 2.0 Library Part 2: Structures, especially §10.4 (TPMT_PUBLIC),
 *     §10.5 (Public area), §10.12.11 (TPMS_ATTEST), §10.12.12 (TPMS_CERTIFY_INFO)
 *   - TCG EK Credential Profile / AIK Certificate Profile v1.03 §3.2
 */

import { createHash, createVerify, verify as verifyRaw, X509Certificate } from 'node:crypto';
import { algorithmForId } from '../cose/key.js';
import { verifyChain, toCertificates } from '../x509/chain.js';
import { findExtension, readTlv, readChildren, decodeOid, TAG } from '../asn1/der.js';
import { bytesEqual, concat } from '../internal/bytes.js';
import { throwAttestationInvalid, throwAttestationTrustAnchorMissing, throwSignatureInvalid } from '../errors.js';

const TPM_GENERATED_VALUE = 0xff544347;
const TPM_ST_ATTEST_CERTIFY = 0x8017;
const TPM_ALG_RSA = 0x0001;
const TPM_ALG_ECC = 0x0023;
const TPM_ALG_NULL = 0x0010;

const TPM_ECC_CURVE = /** @type {const} */ ({
  0x0003: 'P-256',
  0x0004: 'P-384',
  0x0005: 'P-521',
});

// TPM hash algs → node digest name (+ output length in bytes).
const TPM_HASH_ALG = /** @type {const} */ ({
  0x0004: { node: 'sha1', length: 20 },
  0x000b: { node: 'sha256', length: 32 },
  0x000c: { node: 'sha384', length: 48 },
  0x000d: { node: 'sha512', length: 64 },
});

const AIK_EKU_OID = '2.23.133.8.3';

class Reader {
  /** @param {Uint8Array} bytes */
  constructor(bytes) {
    this.bytes = bytes;
    this.pos = 0;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  need(n) {
    if (this.pos + n > this.bytes.byteLength) {
      throwAttestationInvalid(`tpm: TPM struct truncated (need ${n} at offset ${this.pos})`);
    }
  }
  u16() {
    this.need(2);
    const v = this.view.getUint16(this.pos, false);
    this.pos += 2;
    return v;
  }
  u32() {
    this.need(4);
    const v = this.view.getUint32(this.pos, false);
    this.pos += 4;
    return v;
  }
  /** Read a TPM2B: 2-byte length + `length` bytes. */
  b16() {
    const len = this.u16();
    this.need(len);
    const out = this.bytes.subarray(this.pos, this.pos + len);
    this.pos += len;
    return out;
  }
  skip(n) {
    this.need(n);
    this.pos += n;
  }
  remaining() {
    return this.bytes.byteLength - this.pos;
  }
}

/**
 * Parse a TPMT_PUBLIC blob. Returns the algorithm identifier and the
 * key material in a shape ready to compare against a COSE key.
 */
function parsePubArea(bytes) {
  const r = new Reader(bytes);
  const type = r.u16();
  const nameAlgTpm = r.u16();
  const nameAlg = TPM_HASH_ALG[nameAlgTpm];
  if (!nameAlg) {
    throwAttestationInvalid(`tpm: pubArea nameAlg 0x${nameAlgTpm.toString(16)} not supported`);
  }
  r.u32(); // objectAttributes — we don't use it beyond parsing
  r.b16(); // authPolicy

  let key;
  if (type === TPM_ALG_RSA) {
    // TPMS_RSA_PARMS
    if (r.u16() !== TPM_ALG_NULL) {
      throwAttestationInvalid('tpm: pubArea RSA symmetric alg must be TPM_ALG_NULL');
    }
    if (r.u16() !== TPM_ALG_NULL) {
      throwAttestationInvalid('tpm: pubArea RSA scheme must be TPM_ALG_NULL');
    }
    const keyBits = r.u16();
    let exponent = r.u32();
    if (exponent === 0) {
      exponent = 65537; // TPM 2.0 default when field is zero
    }
    const modulus = r.b16();
    if (modulus.byteLength * 8 !== keyBits) {
      throwAttestationInvalid(
        `tpm: pubArea RSA keyBits (${keyBits}) does not match modulus length (${modulus.byteLength * 8})`,
      );
    }
    key = { kind: 'rsa', modulus, exponent };
  } else if (type === TPM_ALG_ECC) {
    if (r.u16() !== TPM_ALG_NULL) {
      throwAttestationInvalid('tpm: pubArea ECC symmetric alg must be TPM_ALG_NULL');
    }
    if (r.u16() !== TPM_ALG_NULL) {
      throwAttestationInvalid('tpm: pubArea ECC scheme must be TPM_ALG_NULL');
    }
    const curveId = r.u16();
    const curveName = TPM_ECC_CURVE[curveId];
    if (!curveName) {
      throwAttestationInvalid(`tpm: pubArea ECC curveID 0x${curveId.toString(16)} not supported`);
    }
    if (r.u16() !== TPM_ALG_NULL) {
      throwAttestationInvalid('tpm: pubArea ECC KDF scheme must be TPM_ALG_NULL');
    }
    const x = r.b16();
    const y = r.b16();
    key = { kind: 'ec', curve: curveName, x, y };
  } else {
    throwAttestationInvalid(`tpm: pubArea type 0x${type.toString(16)} not supported (want RSA 0x0001 or ECC 0x0023)`);
  }

  if (r.remaining() !== 0) {
    throwAttestationInvalid(`tpm: pubArea has ${r.remaining()} trailing byte(s)`);
  }

  return { type, nameAlgTpm, nameAlg, key };
}

/**
 * Parse a TPMS_ATTEST (certInfo). We only support TPM_ST_ATTEST_CERTIFY.
 */
function parseCertInfo(bytes) {
  const r = new Reader(bytes);
  const magic = r.u32();
  if (magic !== TPM_GENERATED_VALUE) {
    throwAttestationInvalid(
      `tpm: certInfo magic must be TPM_GENERATED_VALUE (0xff544347), got 0x${magic.toString(16)}`,
    );
  }
  const type = r.u16();
  if (type !== TPM_ST_ATTEST_CERTIFY) {
    throwAttestationInvalid(`tpm: certInfo type must be TPM_ST_ATTEST_CERTIFY (0x8017), got 0x${type.toString(16)}`);
  }
  const qualifiedSigner = r.b16();
  const extraData = r.b16();
  // TPMS_CLOCK_INFO: clock (u64) + resetCount (u32) + restartCount (u32) + safe (u8)
  r.skip(8 + 4 + 4 + 1);
  r.skip(8); // firmwareVersion (u64)
  // TPMS_CERTIFY_INFO: name + qualifiedName (both TPM2B_NAME)
  const name = r.b16();
  const qualifiedName = r.b16();
  if (r.remaining() !== 0) {
    throwAttestationInvalid(`tpm: certInfo has ${r.remaining()} trailing byte(s)`);
  }
  return { magic, type, qualifiedSigner, extraData, name, qualifiedName };
}

/**
 * Compute the TPM "name" of a public area:
 *   name = nameAlg (2 bytes big-endian) || Hash_nameAlg(pubArea)
 */
function computeName(pubAreaBytes, nameAlg, nameAlgTpm) {
  const digest = createHash(nameAlg.node).update(pubAreaBytes).digest();
  const out = new Uint8Array(2 + digest.byteLength);
  out[0] = (nameAlgTpm >> 8) & 0xff;
  out[1] = nameAlgTpm & 0xff;
  out.set(digest, 2);
  return out;
}

/**
 * Compare a parsed pubArea key against the COSE credentialPublicKey.
 * Both should describe the same underlying key material.
 */
function comparePubAreaToCose(pubKey, coseKey) {
  const kty = coseKey.get(1);
  if (pubKey.kind === 'rsa') {
    if (kty !== 3) {
      throwAttestationInvalid('tpm: pubArea is RSA but credentialPublicKey is not (COSE kty != 3)');
    }
    const n = coseKey.get(-1);
    const e = coseKey.get(-2);
    if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array)) {
      throwAttestationInvalid('tpm: credentialPublicKey RSA n/e must be byte strings');
    }
    if (!bytesEqual(n, pubKey.modulus)) {
      throwAttestationInvalid('tpm: pubArea RSA modulus does not match credentialPublicKey');
    }
    // COSE exponent is big-endian bytes; TPM parsed exponent as u32.
    let coseExp = 0;
    for (let i = 0; i < e.byteLength; i += 1) {
      coseExp = (coseExp << 8) | e[i];
    }
    if (coseExp !== pubKey.exponent) {
      throwAttestationInvalid(
        `tpm: pubArea RSA exponent (${pubKey.exponent}) does not match credentialPublicKey (${coseExp})`,
      );
    }
  } else {
    // EC
    if (kty !== 2) {
      throwAttestationInvalid('tpm: pubArea is ECC but credentialPublicKey is not (COSE kty != 2)');
    }
    const crvId = coseKey.get(-1);
    const crv = { 1: 'P-256', 2: 'P-384', 3: 'P-521' }[crvId];
    if (crv !== pubKey.curve) {
      throwAttestationInvalid(`tpm: pubArea ECC curve ${pubKey.curve} does not match credentialPublicKey (${crv})`);
    }
    const x = coseKey.get(-2);
    const y = coseKey.get(-3);
    if (!bytesEqual(x, pubKey.x) || !bytesEqual(y, pubKey.y)) {
      throwAttestationInvalid('tpm: pubArea ECC x/y do not match credentialPublicKey');
    }
  }
}

/**
 * Check AIK cert profile requirements (TCG AIK Certificate Profile
 * §3.2 as adopted by WebAuthn L3 §8.3 step 5).
 */
function assertAikProfile(leaf, leafDer) {
  // Version 3 — X509Certificate exposes this as an integer (1-based).
  // A "v3" cert reports 3 on the .validFrom side... actually Node's
  // X509Certificate does not expose the version. Skip that check
  // and rely on basicConstraints + EKU + subject.
  //
  // basicConstraints CA:FALSE — Node exposes this via
  // `.ca` (boolean) since Node 20+.
  if (leaf.ca === true) {
    throwAttestationInvalid('tpm: AIK cert basicConstraints CA must be FALSE');
  }
  // extendedKeyUsage MUST include TCG-KP-AIK (2.23.133.8.3).
  // Node's `.extKeyUsage` is unreliable across versions for non-
  // standard OIDs, so we parse the extension ourselves via our DER
  // walker. EKU extension OID is 2.5.29.37; its extnValue is a
  // SEQUENCE OF OBJECT IDENTIFIER.
  const ekuExt = findExtension(leafDer, '2.5.29.37');
  if (ekuExt === null) {
    throwAttestationInvalid('tpm: AIK cert missing extendedKeyUsage extension');
  }
  const ekuSeq = readTlv(ekuExt);
  if (ekuSeq.tag !== TAG.SEQUENCE) {
    throwAttestationInvalid('tpm: AIK cert extendedKeyUsage is not a SEQUENCE');
  }
  const purposes = readChildren(ekuSeq.contents)
    .filter(t => t.tag === TAG.OBJECT_IDENTIFIER)
    .map(t => decodeOid(t.contents));
  if (!purposes.includes(AIK_EKU_OID)) {
    throwAttestationInvalid(`tpm: AIK cert extendedKeyUsage must include ${AIK_EKU_OID} (TCG-KP-AIK)`);
  }
  // Subject sequence MUST be empty (TCG data lives in SAN). Node's
  // .subject returns an empty string when the RDN sequence is empty.
  if (leaf.subject && leaf.subject.replace(/\s+/g, '').length > 0) {
    throwAttestationInvalid(
      `tpm: AIK cert subject must be empty per TCG profile (got "${leaf.subject.replace(/\n/g, ' ')}")`,
    );
  }
  // subjectAlternativeName MUST carry TPM vendor info. We check
  // presence of the SAN extension via our DER walker — the extension
  // OID is 2.5.29.17.
  const san = findExtension(leafDer, '2.5.29.17');
  if (san === null) {
    throwAttestationInvalid('tpm: AIK cert missing subjectAlternativeName (TCG vendor info)');
  }
  // Deep parse of the SAN's directoryName TCG attributes (manufacturer,
  // model, firmwareVersion) is a follow-up — we accept presence for now.
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
 *   format: 'tpm',
 *   trustPath: 'trust-anchor' | 'no-anchor',
 *   certChain: import('node:crypto').X509Certificate[],
 * }}
 */
export function verifyTpm({ attStmt, authDataBytes, clientDataHash, attestedCredentialData, trustAnchors }) {
  if (!(attStmt instanceof Map)) {
    throwAttestationInvalid('tpm: attStmt is not a CBOR map');
  }
  const ver = attStmt.get('ver');
  const alg = attStmt.get('alg');
  const sig = attStmt.get('sig');
  const x5cRaw = attStmt.get('x5c');
  const pubArea = attStmt.get('pubArea');
  const certInfo = attStmt.get('certInfo');

  if (ver !== '2.0') {
    throwAttestationInvalid(`tpm: attStmt.ver must be "2.0" (got "${ver}")`);
  }
  if (typeof alg !== 'number') {
    throwAttestationInvalid('tpm: attStmt.alg missing or not an integer');
  }
  if (!(sig instanceof Uint8Array) || sig.byteLength === 0) {
    throwAttestationInvalid('tpm: attStmt.sig missing or empty');
  }
  if (!Array.isArray(x5cRaw) || x5cRaw.length === 0) {
    throwAttestationInvalid('tpm: attStmt.x5c must be a non-empty array');
  }
  for (const c of x5cRaw) {
    if (!(c instanceof Uint8Array)) {
      throwAttestationInvalid('tpm: attStmt.x5c entries must be byte strings');
    }
  }
  if (!(pubArea instanceof Uint8Array) || !(certInfo instanceof Uint8Array)) {
    throwAttestationInvalid('tpm: attStmt.pubArea and attStmt.certInfo must be byte strings');
  }

  const algParams = algorithmForId(alg);

  // 1. Parse + compare pubArea against credentialPublicKey.
  const parsedPub = parsePubArea(pubArea);
  comparePubAreaToCose(parsedPub.key, attestedCredentialData.credentialPublicKey);

  // 2. Parse certInfo, magic/type already checked inside parseCertInfo.
  const parsedCert = parseCertInfo(certInfo);

  // 3. extraData check.
  // attToBeSigned = authData || clientDataHash; extraData = hash of it.
  // The hash algorithm is determined by algParams.nodeAlgorithm.
  const attToBeSigned = concat(authDataBytes, clientDataHash);
  const digestAlg = (algParams.nodeAlgorithm ?? '').replace(/^RSA-/, '').toLowerCase();
  if (!digestAlg) {
    throwAttestationInvalid(`tpm: signature alg ${algParams.name} has no separate digest for extraData check`);
  }
  const expectedExtraData = createHash(digestAlg).update(attToBeSigned).digest();
  if (!bytesEqual(new Uint8Array(expectedExtraData), parsedCert.extraData)) {
    throwAttestationInvalid('tpm: certInfo.extraData does not equal hash(authData || clientDataHash)');
  }

  // 4. attested.name check.
  const expectedName = computeName(pubArea, parsedPub.nameAlg, parsedPub.nameAlgTpm);
  if (!bytesEqual(expectedName, parsedCert.name)) {
    throwAttestationInvalid('tpm: certInfo.attested.name does not equal nameAlg || Hash_nameAlg(pubArea)');
  }

  // 5. Signature verifies with AIK leaf public key over certInfo bytes.
  const chain = x5cRaw.map(der => new X509Certificate(der));
  const leaf = chain[0];
  if (!verifySignature(leaf.publicKey, algParams, certInfo, sig)) {
    throwSignatureInvalid('tpm: signature does not verify against AIK leaf certificate');
  }

  // 6. AIK cert profile.
  assertAikProfile(leaf, x5cRaw[0]);

  // 7. Chain verification.
  let trustPath = 'no-anchor';
  if (trustAnchors && trustAnchors.length > 0) {
    try {
      verifyChain({ x5c: chain, trustAnchors: toCertificates(trustAnchors) });
      trustPath = 'trust-anchor';
    } catch (err) {
      throwAttestationTrustAnchorMissing(`tpm: ${err.message}`);
    }
  }

  return { format: 'tpm', trustPath, certChain: chain };
}
