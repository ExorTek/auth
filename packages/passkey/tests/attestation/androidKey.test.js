import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash, createPrivateKey, createSign, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { base64url } from '@exortek/crypto/encode';
import { verifyAndroidKey } from '../../src/attestation/androidKey.js';
import { PasskeyError, ErrorCode } from '../../src/errors.js';
import { coseEs256, hex } from '../_helpers/webauthnFixture.js';

const OPENSSL = 'openssl';
const HAS_OPENSSL = (() => {
  try {
    execSync(`${OPENSSL} version`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

const WORK = join(tmpdir(), 'passkey-android-key-attestation-tests');
if (HAS_OPENSSL && !existsSync(WORK)) {
  mkdirSync(WORK, { recursive: true });
}

/**
 * Encode a minimal KeyDescription DER for the extension body.
 * Layout with the challenge at index 4:
 *   SEQUENCE {
 *     INTEGER 3,          -- attestationVersion
 *     ENUMERATED 2,       -- attestationSecurityLevel = STRONGBOX
 *     INTEGER 4,          -- keymasterVersion
 *     ENUMERATED 1,       -- keymasterSecurityLevel = TRUSTED_ENVIRONMENT
 *     OCTET STRING challenge (32 bytes),
 *     OCTET STRING uniqueId (0 bytes),
 *     SEQUENCE { }        -- softwareEnforced (empty for tests)
 *     SEQUENCE { }        -- hardwareEnforced (empty for tests)
 *   }
 */
function encodeKeyDescription(challenge32, { allApplications = false } = {}) {
  // softwareEnforced: empty, or carrying allApplications [600] EXPLICIT
  // NULL (tag BF 84 58, then NULL 05 00) to exercise the §8.4 step-4
  // rejection.
  const softwareEnforced = allApplications
    ? Buffer.from([0x30, 0x06, 0xbf, 0x84, 0x58, 0x02, 0x05, 0x00])
    : Buffer.from([0x30, 0x00]);
  const parts = [
    // INTEGER 3
    Buffer.from([0x02, 0x01, 0x03]),
    // ENUMERATED 2
    Buffer.from([0x0a, 0x01, 0x02]),
    // INTEGER 4
    Buffer.from([0x02, 0x01, 0x04]),
    // ENUMERATED 1
    Buffer.from([0x0a, 0x01, 0x01]),
    // OCTET STRING challenge (short-form length, 32 bytes)
    Buffer.concat([Buffer.from([0x04, challenge32.length]), Buffer.from(challenge32)]),
    // OCTET STRING (empty uniqueId)
    Buffer.from([0x04, 0x00]),
    // SEQUENCE softwareEnforced (empty, or with allApplications [600])
    softwareEnforced,
    // SEQUENCE hardwareEnforced (empty)
    Buffer.from([0x30, 0x00]),
  ];
  const body = Buffer.concat(parts);
  const header = Buffer.from([0x30, body.length]); // Short-form (< 128 bytes)
  return Buffer.concat([header, body]);
}

/**
 * Generate an EC P-256 keypair and self-signed cert carrying the
 * Android Key attestation extension with `challenge32`.
 */
function mintAndroidKeyCert(challenge32, keyDescOpts = {}) {
  const keyPath = join(WORK, 'ak.key');
  const certPath = join(WORK, 'ak.pem');
  const cnfPath = join(WORK, 'ak.cnf');
  execSync(`${OPENSSL} ecparam -name P-256 -genkey -noout -out ${keyPath}`, { stdio: 'ignore' });

  const extDer = encodeKeyDescription(challenge32, keyDescOpts);
  const extHex = extDer.toString('hex').match(/../g).join(':');

  writeFileSync(
    cnfPath,
    [
      '[req]',
      'prompt = no',
      'distinguished_name = dn',
      'req_extensions = v3_ext',
      '[dn]',
      'CN = Android Key Attestation Test',
      '[v3_ext]',
      `1.3.6.1.4.1.11129.2.1.17 = DER:${extHex}`,
    ].join('\n'),
  );

  const csrPath = join(WORK, 'ak.csr');
  execSync(`${OPENSSL} req -new -key ${keyPath} -out ${csrPath} -config ${cnfPath}`, { stdio: 'ignore' });
  execSync(
    `${OPENSSL} x509 -req -in ${csrPath} -signkey ${keyPath} -days 3650 -sha256 -out ${certPath} -extfile ${cnfPath} -extensions v3_ext`,
    { stdio: 'ignore' },
  );
  const pem = readFileSync(certPath, 'utf8');
  const keyPem = readFileSync(keyPath, 'utf8');
  const cert = new X509Certificate(pem);
  const jwk = cert.publicKey.export({ format: 'jwk' });
  return {
    keyPem,
    pem,
    der: cert.raw,
    x: new Uint8Array(base64url.decode(jwk.x)),
    y: new Uint8Array(base64url.decode(jwk.y)),
  };
}

function buildAndroidKeyInputs({ rpId, credentialId, cert }) {
  const rpIdHash = new Uint8Array(createHash('sha256').update(rpId).digest());
  const authDataBytes = new Uint8Array(37 + credentialId.byteLength + 18);
  authDataBytes.set(rpIdHash, 0);
  authDataBytes[32] = 0x41;
  const credLen = new DataView(authDataBytes.buffer, 53, 2);
  credLen.setUint16(0, credentialId.byteLength, false);
  authDataBytes.set(credentialId, 55);

  const clientDataHash = new Uint8Array(createHash('sha256').update('client-data-hash-here-32-bytes!!').digest());

  const attestedCredentialData = {
    aaguid: new Uint8Array(16),
    aaguidString: '00000000-0000-0000-0000-000000000000',
    credentialId,
    credentialPublicKey: coseEs256(cert.x, cert.y),
    credentialPublicKeyBytes: new Uint8Array(0),
  };

  return { authDataBytes, clientDataHash, attestedCredentialData };
}

function signAttestation({ authDataBytes, clientDataHash, cert }) {
  const signed = new Uint8Array(authDataBytes.byteLength + clientDataHash.byteLength);
  signed.set(authDataBytes, 0);
  signed.set(clientDataHash, authDataBytes.byteLength);
  const sig = createSign('SHA256')
    .update(signed)
    .sign({ key: createPrivateKey(cert.keyPem), dsaEncoding: 'der' });
  return new Uint8Array(sig);
}

describe('android-key attestation — happy path', { skip: !HAS_OPENSSL ? 'openssl not installed' : false }, () => {
  test('verifies a well-formed android-key statement', () => {
    const credentialId = hex('c0ffee');
    // Compute clientDataHash first so we can bake it into the cert.
    const clientDataHash = new Uint8Array(createHash('sha256').update('client-data-hash-here-32-bytes!!').digest());
    const cert = mintAndroidKeyCert(clientDataHash);
    const inputs = buildAndroidKeyInputs({ rpId: 'example.com', credentialId, cert });
    const sig = signAttestation({ ...inputs, cert });
    const attStmt = new Map([
      ['alg', -7],
      ['sig', sig],
      ['x5c', [cert.der]],
    ]);
    const out = verifyAndroidKey({ attStmt, ...inputs });
    assert.equal(out.format, 'android-key');
    assert.equal(out.trustPath, 'no-anchor');
  });
});

describe('android-key attestation — rejections', { skip: !HAS_OPENSSL ? 'openssl not installed' : false }, () => {
  test('rejects when attestationChallenge does not match clientDataHash', () => {
    const credentialId = hex('01');
    // Bake a WRONG challenge into the extension.
    const cert = mintAndroidKeyCert(new Uint8Array(32));
    const inputs = buildAndroidKeyInputs({ rpId: 'example.com', credentialId, cert });
    const sig = signAttestation({ ...inputs, cert });
    const attStmt = new Map([
      ['alg', -7],
      ['sig', sig],
      ['x5c', [cert.der]],
    ]);
    assert.throws(
      () => verifyAndroidKey({ attStmt, ...inputs }),
      err => err instanceof PasskeyError && err.code === ErrorCode.ATTESTATION_INVALID,
    );
  });

  test('rejects when KeyDescription carries allApplications [600]', () => {
    const credentialId = hex('0a');
    const clientDataHash = new Uint8Array(createHash('sha256').update('client-data-hash-here-32-bytes!!').digest());
    // Correct challenge + valid signature, but the key is scoped to
    // allApplications — must be rejected on the §8.4 step-4 gate.
    const cert = mintAndroidKeyCert(clientDataHash, { allApplications: true });
    const inputs = buildAndroidKeyInputs({ rpId: 'example.com', credentialId, cert });
    const sig = signAttestation({ ...inputs, cert });
    const attStmt = new Map([
      ['alg', -7],
      ['sig', sig],
      ['x5c', [cert.der]],
    ]);
    assert.throws(
      () => verifyAndroidKey({ attStmt, ...inputs }),
      err =>
        err instanceof PasskeyError &&
        err.code === ErrorCode.ATTESTATION_INVALID &&
        /allApplications/.test(err.message),
    );
  });

  test('rejects when signature is bad', () => {
    const credentialId = hex('02');
    const clientDataHash = new Uint8Array(createHash('sha256').update('client-data-hash-here-32-bytes!!').digest());
    const cert = mintAndroidKeyCert(clientDataHash);
    const inputs = buildAndroidKeyInputs({ rpId: 'example.com', credentialId, cert });
    const attStmt = new Map([
      ['alg', -7],
      ['sig', new Uint8Array(64)], // zeroed signature — will not verify
      ['x5c', [cert.der]],
    ]);
    assert.throws(
      () => verifyAndroidKey({ attStmt, ...inputs }),
      err => err instanceof PasskeyError && err.code === ErrorCode.SIGNATURE_INVALID,
    );
  });

  test('rejects when leaf public key does not match credentialPublicKey', () => {
    const credentialId = hex('03');
    const clientDataHash = new Uint8Array(createHash('sha256').update('client-data-hash-here-32-bytes!!').digest());
    const cert = mintAndroidKeyCert(clientDataHash);
    const inputs = buildAndroidKeyInputs({ rpId: 'example.com', credentialId, cert });
    // Swap credentialPublicKey to a real, but different, EC point.
    const other = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    inputs.attestedCredentialData.credentialPublicKey = coseEs256(
      new Uint8Array(base64url.decode(other.x)),
      new Uint8Array(base64url.decode(other.y)),
    );
    const sig = signAttestation({ ...inputs, cert });
    const attStmt = new Map([
      ['alg', -7],
      ['sig', sig],
      ['x5c', [cert.der]],
    ]);
    assert.throws(() => verifyAndroidKey({ attStmt, ...inputs }), /SPKI mismatch/);
  });
});
