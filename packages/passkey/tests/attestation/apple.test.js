import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash, createPublicKey, X509Certificate } from 'node:crypto';
import { base64url } from '@exortek/crypto/encode';
import { verifyApple } from '../../src/attestation/apple.js';
import { PasskeyError, ErrorCode } from '../../src/errors.js';
import { coseEs256, hex } from '../_helpers/webauthnFixture.js';

// Apple attestation verification is tightly coupled to (a) the leaf
// cert carrying a specific nonce extension whose value equals
// SHA-256(authData || clientDataHash), and (b) the leaf cert's
// public key matching the credentialPublicKey. Because the nonce
// is a hash of runtime data, we can't pre-generate a fixture — we
// generate a fresh cert per test via openssl.

const OPENSSL = 'openssl';
const HAS_OPENSSL = (() => {
  try {
    execSync(`${OPENSSL} version`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

const WORK = join(tmpdir(), 'passkey-apple-attestation-tests');
if (HAS_OPENSSL && !existsSync(WORK)) {
  mkdirSync(WORK, { recursive: true });
}

/**
 * Build authData / clientDataHash for a fixed rpId + credential key
 * `(x, y)`. Returns the pair plus their `nonceToHash` SHA-256, which
 * the caller uses to mint a leaf cert whose extension carries that
 * nonce.
 */
function buildInputs({ rpId, credentialId, x, y }) {
  const rpIdHash = new Uint8Array(createHash('sha256').update(rpId).digest());
  const flags = 0x41; // UP + AT
  const counter = new Uint8Array(4);
  const aaguid = new Uint8Array(16);
  const credIdLen = new Uint8Array(2);
  new DataView(credIdLen.buffer).setUint16(0, credentialId.byteLength, false);
  // We don't actually re-parse authData here — the verifier doesn't
  // parse it either, only concatenates it with clientDataHash and
  // hashes. But we still include a plausible attested-cred body so
  // if a future refactor uses parseAuthData it stays consistent.
  const authDataBytes = new Uint8Array(32 + 1 + 4 + 16 + 2 + credentialId.byteLength);
  let ap = 0;
  authDataBytes.set(rpIdHash, ap);
  ap += 32;
  authDataBytes[ap++] = flags;
  authDataBytes.set(counter, ap);
  ap += 4;
  authDataBytes.set(aaguid, ap);
  ap += 16;
  authDataBytes.set(credIdLen, ap);
  ap += 2;
  authDataBytes.set(credentialId, ap);

  const clientDataHash = new Uint8Array(createHash('sha256').update('client-data').digest());

  const combined = new Uint8Array(authDataBytes.byteLength + clientDataHash.byteLength);
  combined.set(authDataBytes, 0);
  combined.set(clientDataHash, authDataBytes.byteLength);
  const nonce = new Uint8Array(createHash('sha256').update(combined).digest());

  const attestedCredentialData = {
    aaguid,
    aaguidString: '00000000-0000-0000-0000-000000000000',
    credentialId,
    credentialPublicKey: coseEs256(x, y),
    credentialPublicKeyBytes: new Uint8Array(0),
  };

  return { authDataBytes, clientDataHash, attestedCredentialData, nonce };
}

describe('apple attestation — happy path', { skip: !HAS_OPENSSL ? 'openssl not installed' : false }, () => {
  test('verifies with matching nonce + matching leaf key', () => {
    // 1. Generate a fixed EC P-256 key. 2. Build authData +
    // clientDataHash with that key's public coordinates. 3. Compute
    // the nonce = SHA-256(authData || clientDataHash). 4. Sign a
    // self-signed cert with the same key, carrying the nonce
    // extension. 5. Verify.
    const kp = generateFixedKey();
    const inputs = buildInputs({ rpId: 'example.com', credentialId: hex('cafefeed'), x: kp.x, y: kp.y });
    const cert = signCertWithNonce(kp, inputs.nonce);

    const out = verifyApple({
      attStmt: new Map([['x5c', [cert.der]]]),
      authDataBytes: inputs.authDataBytes,
      clientDataHash: inputs.clientDataHash,
      attestedCredentialData: inputs.attestedCredentialData,
    });
    assert.equal(out.format, 'apple');
    assert.equal(out.trustPath, 'no-anchor');
    assert.equal(out.certChain.length, 1);
  });
});

// Generate a P-256 keypair once via openssl and reuse for multiple
// cert issuances.
function generateFixedKey() {
  const keyPath = join(WORK, 'fixed.key');
  execSync(`${OPENSSL} ecparam -name P-256 -genkey -noout -out ${keyPath}`, { stdio: 'ignore' });
  const pem = readFileSync(keyPath, 'utf8');
  const pk = createPublicKey({ key: pem, format: 'pem' });
  const jwk = pk.export({ format: 'jwk' });
  return {
    keyPath,
    x: new Uint8Array(base64url.decode(jwk.x)),
    y: new Uint8Array(base64url.decode(jwk.y)),
  };
}

// Sign a self-signed cert reusing the pre-existing key, carrying the
// Apple nonce extension with `nonce32`.
function signCertWithNonce(kp, nonce32) {
  const nonceHex = Buffer.from(nonce32).toString('hex');
  const formatted = nonceHex.match(/../g).join(':');
  const extDer = `30:24:a1:22:04:20:${formatted}`;

  const cnfPath = join(WORK, 'signed.cnf');
  writeFileSync(
    cnfPath,
    [
      '[req]',
      'prompt = no',
      'distinguished_name = dn',
      'req_extensions = v3_ext',
      '[dn]',
      'CN = Apple Anonymous Attestation Test',
      '[v3_ext]',
      `1.2.840.113635.100.8.2 = DER:${extDer}`,
    ].join('\n'),
  );

  const csrPath = join(WORK, 'signed.csr');
  const certPath = join(WORK, 'signed.pem');
  execSync(`${OPENSSL} req -new -key ${kp.keyPath} -out ${csrPath} -config ${cnfPath}`, { stdio: 'ignore' });
  execSync(
    `${OPENSSL} x509 -req -in ${csrPath} -signkey ${kp.keyPath} -days 3650 -sha256 -out ${certPath} -extfile ${cnfPath} -extensions v3_ext`,
    { stdio: 'ignore' },
  );
  const pem = readFileSync(certPath, 'utf8');
  const cert = new X509Certificate(pem);
  return { pem, der: cert.raw };
}

describe('apple attestation — rejections', { skip: !HAS_OPENSSL ? 'openssl not installed' : false }, () => {
  test('rejects when nonce does not match hashed input', () => {
    const kp = generateFixedKey();
    const inputs = buildInputs({ rpId: 'example.com', credentialId: hex('01'), x: kp.x, y: kp.y });
    const cert = signCertWithNonce(kp, new Uint8Array(32)); // wrong nonce (all zeros)
    assert.throws(
      () =>
        verifyApple({
          attStmt: new Map([['x5c', [cert.der]]]),
          authDataBytes: inputs.authDataBytes,
          clientDataHash: inputs.clientDataHash,
          attestedCredentialData: inputs.attestedCredentialData,
        }),
      err => err instanceof PasskeyError && err.code === ErrorCode.ATTESTATION_INVALID,
    );
  });

  test('rejects when leaf key does not match credential key', () => {
    const kp = generateFixedKey();
    const inputs = buildInputs({ rpId: 'example.com', credentialId: hex('02'), x: kp.x, y: kp.y });
    const cert = signCertWithNonce(kp, inputs.nonce);
    // Swap credentialPublicKey for a different EC point.
    const other = new Uint8Array(32).fill(0x11);
    inputs.attestedCredentialData.credentialPublicKey = coseEs256(other, other);
    assert.throws(
      () =>
        verifyApple({
          attStmt: new Map([['x5c', [cert.der]]]),
          authDataBytes: inputs.authDataBytes,
          clientDataHash: inputs.clientDataHash,
          attestedCredentialData: inputs.attestedCredentialData,
        }),
      /leaf public key does not match credential public key/,
    );
  });

  test('rejects when attStmt carries a sig field', () => {
    const kp = generateFixedKey();
    const inputs = buildInputs({ rpId: 'example.com', credentialId: hex('03'), x: kp.x, y: kp.y });
    const cert = signCertWithNonce(kp, inputs.nonce);
    assert.throws(
      () =>
        verifyApple({
          attStmt: new Map([
            ['x5c', [cert.der]],
            ['sig', new Uint8Array([1, 2, 3])],
          ]),
          authDataBytes: inputs.authDataBytes,
          clientDataHash: inputs.clientDataHash,
          attestedCredentialData: inputs.attestedCredentialData,
        }),
      /must not carry a sig field/,
    );
  });

  test('rejects when x5c is empty', () => {
    const kp = generateFixedKey();
    const inputs = buildInputs({ rpId: 'example.com', credentialId: hex('04'), x: kp.x, y: kp.y });
    assert.throws(
      () =>
        verifyApple({
          attStmt: new Map([['x5c', []]]),
          authDataBytes: inputs.authDataBytes,
          clientDataHash: inputs.clientDataHash,
          attestedCredentialData: inputs.attestedCredentialData,
        }),
      /x5c must be a non-empty array/,
    );
  });
});
