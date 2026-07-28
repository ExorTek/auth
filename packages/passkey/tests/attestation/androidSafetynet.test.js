import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash, createPrivateKey, createSign, X509Certificate } from 'node:crypto';
import { base64url } from '@exortek/crypto/encode';
import { verifyAndroidSafetynet } from '../../src/attestation/androidSafetynet.js';
import { PasskeyError, ErrorCode } from '../../src/errors.js';
import { hex } from '../_helpers/webauthnFixture.js';

const OPENSSL = 'openssl';
const HAS_OPENSSL = (() => {
  try {
    execSync(`${OPENSSL} version`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

const WORK = join(tmpdir(), 'passkey-safetynet-attestation-tests');
if (HAS_OPENSSL && !existsSync(WORK)) {
  mkdirSync(WORK, { recursive: true });
}

/**
 * Mint an RSA-2048 keypair + self-signed cert with subject
 * CN="attest.android.com". Reused across tests.
 */
function mintAttestKey() {
  const keyPath = join(WORK, 'attest.key');
  const certPath = join(WORK, 'attest.pem');
  execSync(`${OPENSSL} genrsa -out ${keyPath} 2048`, { stdio: 'ignore' });
  execSync(
    `${OPENSSL} req -x509 -new -key ${keyPath} -sha256 -days 3650 -out ${certPath} -subj "/CN=attest.android.com"`,
    { stdio: 'ignore' },
  );
  const certPem = readFileSync(certPath, 'utf8');
  const keyPem = readFileSync(keyPath, 'utf8');
  const cert = new X509Certificate(certPem);
  return { keyPem, certPem, certDer: cert.raw };
}

function encodeJsonB64u(obj) {
  return base64url.encode(new TextEncoder().encode(JSON.stringify(obj)));
}

/**
 * Build a full SafetyNet attStmt for the given authData/clientDataHash.
 * Overrides let us test rejection branches.
 */
function buildSafetynetAttStmt({
  authDataBytes,
  clientDataHash,
  key,
  cert,
  overrides = {},
  headerOverrides = {},
  alg = 'RSA-SHA256',
}) {
  const combined = new Uint8Array(authDataBytes.byteLength + clientDataHash.byteLength);
  combined.set(authDataBytes, 0);
  combined.set(clientDataHash, authDataBytes.byteLength);
  const nonce = createHash('sha256').update(combined).digest('base64');

  const payload = {
    nonce,
    timestampMs: Date.now(),
    apkPackageName: 'com.google.android.gms',
    apkDigestSha256: 'aaaaaa==',
    ctsProfileMatch: true,
    apkCertificateDigestSha256: ['bbbbbb=='],
    basicIntegrity: true,
    ...overrides,
  };
  const header = {
    alg: 'RS256',
    x5c: [Buffer.from(cert.certDer).toString('base64')],
    ...headerOverrides,
  };
  const headerB64 = encodeJsonB64u(header);
  const payloadB64 = encodeJsonB64u(payload);
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = createSign(alg).update(signingInput).sign(createPrivateKey(key.keyPem));
  const sigB64 = base64url.encode(new Uint8Array(signature));
  const compact = `${headerB64}.${payloadB64}.${sigB64}`;
  return {
    attStmt: new Map([
      ['ver', '14799021'],
      ['response', new TextEncoder().encode(compact)],
    ]),
    payload,
    header,
  };
}

function makeInputs(rpId, credentialId) {
  const rpIdHash = new Uint8Array(createHash('sha256').update(rpId).digest());
  const authDataBytes = new Uint8Array(37 + credentialId.byteLength + 18);
  authDataBytes.set(rpIdHash, 0);
  authDataBytes[32] = 0x41; // UP + AT
  // counter zeros
  // aaguid zeros — bytes 37..52 (via new Uint8Array(16) already zeroed)
  const credLenView = new DataView(authDataBytes.buffer, 53, 2);
  credLenView.setUint16(0, credentialId.byteLength, false);
  authDataBytes.set(credentialId, 55);
  const clientDataHash = new Uint8Array(createHash('sha256').update('client-data').digest());
  return { authDataBytes, clientDataHash };
}

describe('android-safetynet attestation — happy path', { skip: !HAS_OPENSSL ? 'openssl not installed' : false }, () => {
  test('verifies a well-formed SafetyNet JWS', () => {
    const inputs = makeInputs('example.com', hex('cafe'));
    const key = mintAttestKey();
    const { attStmt } = buildSafetynetAttStmt({ ...inputs, key, cert: key });
    const out = verifyAndroidSafetynet({ attStmt, ...inputs });
    assert.equal(out.format, 'android-safetynet');
    assert.equal(out.ctsProfileMatch, true);
    assert.equal(out.basicIntegrity, true);
    assert.equal(out.trustPath, 'no-anchor');
    assert.equal(out.certChain.length, 1);
  });
});

describe('android-safetynet attestation — rejections', { skip: !HAS_OPENSSL ? 'openssl not installed' : false }, () => {
  test('rejects when nonce does not match', () => {
    const inputs = makeInputs('example.com', hex('01'));
    const key = mintAttestKey();
    const { attStmt } = buildSafetynetAttStmt({
      ...inputs,
      key,
      cert: key,
      overrides: { nonce: 'AAAA' },
    });
    assert.throws(
      () => verifyAndroidSafetynet({ attStmt, ...inputs }),
      err => err instanceof PasskeyError && err.code === ErrorCode.ATTESTATION_INVALID,
    );
  });

  test('rejects when signature is tampered', () => {
    const inputs = makeInputs('example.com', hex('02'));
    const key = mintAttestKey();
    const { attStmt } = buildSafetynetAttStmt({ ...inputs, key, cert: key });
    // Flip low bit of a signature char — stays ASCII (so UTF-8
    // decode still succeeds) but breaks the RSA signature.
    const bytes = attStmt.get('response');
    bytes[bytes.length - 1] ^= 0x01;
    assert.throws(
      () => verifyAndroidSafetynet({ attStmt, ...inputs }),
      err => err instanceof PasskeyError && err.code === ErrorCode.SIGNATURE_INVALID,
    );
  });

  test('rejects when header.alg is not RS256', () => {
    const inputs = makeInputs('example.com', hex('03'));
    const key = mintAttestKey();
    const { attStmt } = buildSafetynetAttStmt({
      ...inputs,
      key,
      cert: key,
      headerOverrides: { alg: 'HS256' },
    });
    assert.throws(() => verifyAndroidSafetynet({ attStmt, ...inputs }), /alg must be "RS256"/);
  });

  test('rejects when basicIntegrity is false', () => {
    const inputs = makeInputs('example.com', hex('04'));
    const key = mintAttestKey();
    const { attStmt } = buildSafetynetAttStmt({
      ...inputs,
      key,
      cert: key,
      overrides: { basicIntegrity: false },
    });
    assert.throws(() => verifyAndroidSafetynet({ attStmt, ...inputs }), /basicIntegrity is not true/);
  });

  test('rejects when ctsProfileMatch is false and enforceCtsCheck (default)', () => {
    const inputs = makeInputs('example.com', hex('05'));
    const key = mintAttestKey();
    const { attStmt } = buildSafetynetAttStmt({
      ...inputs,
      key,
      cert: key,
      overrides: { ctsProfileMatch: false },
    });
    assert.throws(() => verifyAndroidSafetynet({ attStmt, ...inputs }), /ctsProfileMatch is not true/);
  });

  test('accepts ctsProfileMatch=false when enforceCtsCheck: false', () => {
    const inputs = makeInputs('example.com', hex('06'));
    const key = mintAttestKey();
    const { attStmt } = buildSafetynetAttStmt({
      ...inputs,
      key,
      cert: key,
      overrides: { ctsProfileMatch: false },
    });
    const out = verifyAndroidSafetynet({ attStmt, ...inputs, enforceCtsCheck: false });
    assert.equal(out.ctsProfileMatch, false);
  });

  test('rejects when timestampMs outside window', () => {
    const inputs = makeInputs('example.com', hex('07'));
    const key = mintAttestKey();
    const past = Date.now() - 10 * 60_000; // 10 minutes ago
    const { attStmt } = buildSafetynetAttStmt({
      ...inputs,
      key,
      cert: key,
      overrides: { timestampMs: past },
    });
    assert.throws(() => verifyAndroidSafetynet({ attStmt, ...inputs }), /outside the ±/);
  });

  test('rejects when leaf CN is not attest.android.com', () => {
    const inputs = makeInputs('example.com', hex('08'));
    // Mint a cert with a wrong CN.
    const keyPath = join(WORK, 'wrongcn.key');
    const certPath = join(WORK, 'wrongcn.pem');
    execSync(`${OPENSSL} genrsa -out ${keyPath} 2048`, { stdio: 'ignore' });
    execSync(
      `${OPENSSL} req -x509 -new -key ${keyPath} -sha256 -days 3650 -out ${certPath} -subj "/CN=wrong.example.com"`,
      { stdio: 'ignore' },
    );
    const wrongKey = { keyPem: readFileSync(keyPath, 'utf8'), certPem: readFileSync(certPath, 'utf8') };
    wrongKey.certDer = new X509Certificate(wrongKey.certPem).raw;
    const { attStmt } = buildSafetynetAttStmt({ ...inputs, key: wrongKey, cert: wrongKey });
    assert.throws(() => verifyAndroidSafetynet({ attStmt, ...inputs }), /CN must be "attest.android.com"/);
  });
});
