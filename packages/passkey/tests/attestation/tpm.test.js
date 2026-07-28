import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  createSign,
  generateKeyPairSync,
  X509Certificate,
} from 'node:crypto';
import { base64url } from '@exortek/crypto/encode';
import { verifyTpm } from '../../src/attestation/tpm.js';
import { PasskeyError, ErrorCode } from '../../src/errors.js';
import { coseRs256, hex } from '../_helpers/webauthnFixture.js';

const OPENSSL = 'openssl';
const HAS_OPENSSL = (() => {
  try {
    execSync(`${OPENSSL} version`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

const WORK = join(tmpdir(), 'passkey-tpm-attestation-tests');
if (HAS_OPENSSL && !existsSync(WORK)) {
  mkdirSync(WORK, { recursive: true });
}

// TPM constants used by the fixture builder.
const TPM_ALG_RSA = 0x0001;
const TPM_ALG_NULL = 0x0010;
const TPM_ALG_SHA256 = 0x000b;
const TPM_GENERATED_VALUE = 0xff544347;
const TPM_ST_ATTEST_CERTIFY = 0x8017;

function u16(n) {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n, false);
  return b;
}
function u32(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
}
function b16(bytes) {
  return Buffer.concat([Buffer.from(u16(bytes.byteLength)), Buffer.from(bytes)]);
}
function concat(...chunks) {
  return Buffer.concat(chunks.map(c => Buffer.from(c)));
}

/**
 * Build a TPMT_PUBLIC for an RSA credential key.
 *   type       : TPM_ALG_RSA
 *   nameAlg    : TPM_ALG_SHA256
 *   objectAttrs: 0
 *   authPolicy : empty
 *   parameters : TPMS_RSA_PARMS { NULL, NULL, keyBits, exponent }
 *   unique     : TPM2B_PUBLIC_KEY_RSA (modulus)
 */
function buildRsaPubArea({ modulus, exponent }) {
  return concat(
    u16(TPM_ALG_RSA),
    u16(TPM_ALG_SHA256),
    u32(0),
    b16(new Uint8Array(0)),
    // TPMS_RSA_PARMS: symmetric=NULL, scheme=NULL, keyBits, exponent
    u16(TPM_ALG_NULL),
    u16(TPM_ALG_NULL),
    u16(modulus.byteLength * 8),
    u32(exponent),
    // TPMU_PUBLIC_ID: TPM2B_PUBLIC_KEY_RSA
    b16(modulus),
  );
}

/**
 * Build a TPMS_ATTEST for TPM_ST_ATTEST_CERTIFY with the given
 * extraData + name. Clock/firmware fields are zeroed.
 */
function buildCertifyCertInfo({ extraData, name }) {
  return concat(
    u32(TPM_GENERATED_VALUE),
    u16(TPM_ST_ATTEST_CERTIFY),
    b16(new Uint8Array(0)), // qualifiedSigner
    b16(extraData),
    // TPMS_CLOCK_INFO
    new Uint8Array(8), // clock (u64)
    u32(0), // resetCount
    u32(0), // restartCount
    new Uint8Array([0]), // safe
    new Uint8Array(8), // firmwareVersion (u64)
    // TPMS_CERTIFY_INFO
    b16(name),
    b16(new Uint8Array(0)), // qualifiedName
  );
}

function computeTpmName(pubArea) {
  const digest = createHash('sha256').update(pubArea).digest();
  return concat(u16(TPM_ALG_SHA256), digest);
}

/** Mint an AIK RSA-2048 cert with the required TCG profile bits. */
function mintAikCert() {
  const keyPath = join(WORK, 'aik.key');
  const csrPath = join(WORK, 'aik.csr');
  const certPath = join(WORK, 'aik.pem');
  const cnfPath = join(WORK, 'aik.cnf');
  execSync(`${OPENSSL} genrsa -out ${keyPath} 2048`, { stdio: 'ignore' });
  writeFileSync(
    cnfPath,
    [
      '[req]',
      'prompt = no',
      'distinguished_name = dn',
      'req_extensions = v3_ext',
      '[dn]',
      // Empty subject — TCG AIK profile forbids populated Subject;
      // openssl needs at least a placeholder that we then override
      // to empty via the CSR post-processing below is painful, so we
      // use `-subj "/"` at request time instead.
      '[v3_ext]',
      'basicConstraints = critical,CA:FALSE',
      'extendedKeyUsage = 2.23.133.8.3',
      'subjectAltName = DNS:tpm-test.example.com',
    ].join('\n'),
  );
  execSync(`${OPENSSL} req -new -key ${keyPath} -out ${csrPath} -config ${cnfPath} -subj "/"`, { stdio: 'ignore' });
  execSync(
    `${OPENSSL} x509 -req -in ${csrPath} -signkey ${keyPath} -days 3650 -sha256 -out ${certPath} -extfile ${cnfPath} -extensions v3_ext`,
    { stdio: 'ignore' },
  );
  const pem = readFileSync(certPath, 'utf8');
  const keyPem = readFileSync(keyPath, 'utf8');
  const cert = new X509Certificate(pem);
  return { pem, der: cert.raw, keyPem, cert };
}

function buildInputs({ rpId, credentialId, modulus, exponent }) {
  const rpIdHash = new Uint8Array(createHash('sha256').update(rpId).digest());
  const authDataBytes = new Uint8Array(37 + credentialId.byteLength + 18);
  authDataBytes.set(rpIdHash, 0);
  authDataBytes[32] = 0x41;
  const credLen = new DataView(authDataBytes.buffer, 53, 2);
  credLen.setUint16(0, credentialId.byteLength, false);
  authDataBytes.set(credentialId, 55);
  const clientDataHash = new Uint8Array(createHash('sha256').update('tpm-test-client-data').digest());

  // Build exponent as big-endian bytes (COSE convention).
  const eBytes = [];
  let e = exponent;
  while (e > 0) {
    eBytes.unshift(e & 0xff);
    e >>>= 8;
  }

  const attestedCredentialData = {
    aaguid: new Uint8Array(16),
    aaguidString: '00000000-0000-0000-0000-000000000000',
    credentialId,
    credentialPublicKey: coseRs256(modulus, new Uint8Array(eBytes)),
    credentialPublicKeyBytes: new Uint8Array(0),
  };

  return { authDataBytes, clientDataHash, attestedCredentialData };
}

describe('tpm attestation — happy path', { skip: !HAS_OPENSSL ? 'openssl not installed' : false }, () => {
  test('verifies a well-formed TPM 2.0 RSA attestation', () => {
    // Credential RSA key (what the TPM claims to have generated).
    const credKp = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const credJwk = credKp.publicKey.export({ format: 'jwk' });
    const modulus = new Uint8Array(base64url.decode(credJwk.n));
    // Node emits the RSA public exponent as base64url of variable-
    // length big-endian bytes; convert to a canonical unsigned int.
    const eBytes = new Uint8Array(base64url.decode(credJwk.e));
    let exponent = 0;
    for (const b of eBytes) exponent = (exponent << 8) | b;

    const pubArea = buildRsaPubArea({ modulus, exponent });

    // AIK cert + key sign certInfo.
    const aik = mintAikCert();
    const aikKey = createPrivateKey(aik.keyPem);

    const inputs = buildInputs({
      rpId: 'example.com',
      credentialId: hex('deadbeefcafe'),
      modulus,
      exponent,
    });

    // extraData = SHA-256(authData || clientDataHash).
    const attToBeSigned = concat(inputs.authDataBytes, inputs.clientDataHash);
    const extraData = new Uint8Array(createHash('sha256').update(attToBeSigned).digest());
    const name = computeTpmName(pubArea);
    const certInfo = buildCertifyCertInfo({ extraData, name });

    const sig = createSign('RSA-SHA256').update(certInfo).sign(aikKey);
    const attStmt = new Map([
      ['ver', '2.0'],
      ['alg', -257],
      ['sig', new Uint8Array(sig)],
      ['x5c', [aik.der]],
      ['pubArea', new Uint8Array(pubArea)],
      ['certInfo', new Uint8Array(certInfo)],
    ]);

    const out = verifyTpm({ attStmt, ...inputs });
    assert.equal(out.format, 'tpm');
    assert.equal(out.trustPath, 'no-anchor');
    assert.equal(out.certChain.length, 1);
  });
});

describe('tpm attestation — rejections', { skip: !HAS_OPENSSL ? 'openssl not installed' : false }, () => {
  function buildFullFixture() {
    const credKp = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const credJwk = credKp.publicKey.export({ format: 'jwk' });
    const modulus = new Uint8Array(base64url.decode(credJwk.n));
    const eBytes = new Uint8Array(base64url.decode(credJwk.e));
    let exponent = 0;
    for (const b of eBytes) exponent = (exponent << 8) | b;

    const pubArea = buildRsaPubArea({ modulus, exponent });
    const aik = mintAikCert();
    const aikKey = createPrivateKey(aik.keyPem);
    const inputs = buildInputs({
      rpId: 'example.com',
      credentialId: hex('feedbeef'),
      modulus,
      exponent,
    });
    const attToBeSigned = concat(inputs.authDataBytes, inputs.clientDataHash);
    const extraData = new Uint8Array(createHash('sha256').update(attToBeSigned).digest());
    const name = computeTpmName(pubArea);
    const certInfo = buildCertifyCertInfo({ extraData, name });
    const sig = createSign('RSA-SHA256').update(certInfo).sign(aikKey);
    return { pubArea, certInfo, sig, aik, inputs };
  }

  test('rejects when ver is not "2.0"', () => {
    const f = buildFullFixture();
    const attStmt = new Map([
      ['ver', '1.2'],
      ['alg', -257],
      ['sig', new Uint8Array(f.sig)],
      ['x5c', [f.aik.der]],
      ['pubArea', new Uint8Array(f.pubArea)],
      ['certInfo', new Uint8Array(f.certInfo)],
    ]);
    assert.throws(
      () => verifyTpm({ attStmt, ...f.inputs }),
      err => err instanceof PasskeyError && err.code === ErrorCode.ATTESTATION_INVALID,
    );
  });

  test('rejects when certInfo.magic is wrong', () => {
    const f = buildFullFixture();
    // Corrupt magic — first 4 bytes of certInfo.
    const badCertInfo = Buffer.from(f.certInfo);
    badCertInfo[0] = 0x00;
    const attStmt = new Map([
      ['ver', '2.0'],
      ['alg', -257],
      ['sig', new Uint8Array(f.sig)], // sig now doesn't match, but magic check fires first
      ['x5c', [f.aik.der]],
      ['pubArea', new Uint8Array(f.pubArea)],
      ['certInfo', new Uint8Array(badCertInfo)],
    ]);
    assert.throws(() => verifyTpm({ attStmt, ...f.inputs }), /magic must be TPM_GENERATED_VALUE/);
  });

  test('rejects when pubArea key does not match credentialPublicKey', () => {
    const f = buildFullFixture();
    // Regenerate credential public key to a different RSA modulus.
    const other = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' });
    const otherN = new Uint8Array(base64url.decode(other.n));
    const otherE = new Uint8Array(base64url.decode(other.e));
    f.inputs.attestedCredentialData.credentialPublicKey = coseRs256(otherN, otherE);
    const attStmt = new Map([
      ['ver', '2.0'],
      ['alg', -257],
      ['sig', new Uint8Array(f.sig)],
      ['x5c', [f.aik.der]],
      ['pubArea', new Uint8Array(f.pubArea)],
      ['certInfo', new Uint8Array(f.certInfo)],
    ]);
    assert.throws(() => verifyTpm({ attStmt, ...f.inputs }), /modulus does not match/);
  });
});
