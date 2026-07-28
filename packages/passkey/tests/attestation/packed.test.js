import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash, createPrivateKey, createSign, X509Certificate } from 'node:crypto';
import { base64url } from '@exortek/crypto/encode';
import { verifyPacked } from '../../src/attestation/packed.js';
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

const WORK = join(tmpdir(), 'passkey-packed-attestation-tests');
if (HAS_OPENSSL && !existsSync(WORK)) {
  mkdirSync(WORK, { recursive: true });
}

// AAGUID OID 1.3.6.1.4.1.45724.1.1.4 — inner OCTET STRING wraps the
// 16-byte AAGUID.
function encodeAaguidExt(aaguid16) {
  return Buffer.concat([Buffer.from([0x04, 0x10]), Buffer.from(aaguid16)]);
}

/**
 * Generate a self-signed packed attestation leaf certificate.
 * Options:
 *   subject         — DN string
 *   ca              — set basicConstraints CA:TRUE when true
 *   aaguidExt       — 16-byte Uint8Array to embed in the AAGUID extension,
 *                     or null to omit the extension
 */
function mintPackedLeaf({ tag, subject, ca = false, aaguidExt = null }) {
  const keyPath = join(WORK, `pk-${tag}.key`);
  const certPath = join(WORK, `pk-${tag}.pem`);
  const cnfPath = join(WORK, `pk-${tag}.cnf`);
  execSync(`${OPENSSL} ecparam -name P-256 -genkey -noout -out ${keyPath}`, { stdio: 'ignore' });

  const extLines = ['[v3_ext]', `basicConstraints = critical, CA:${ca ? 'TRUE' : 'FALSE'}`];
  if (aaguidExt) {
    const hexBytes = Buffer.from(encodeAaguidExt(aaguidExt)).toString('hex').match(/../g).join(':');
    extLines.push(`1.3.6.1.4.1.45724.1.1.4 = DER:${hexBytes}`);
  }
  writeFileSync(
    cnfPath,
    ['[req]', 'prompt = no', 'distinguished_name = dn', 'req_extensions = v3_ext', '[dn]', subject, ...extLines].join(
      '\n',
    ),
  );

  const csrPath = join(WORK, `pk-${tag}.csr`);
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

function buildPackedInputs({ rpId, credentialId, cert, aaguid }) {
  const rpIdHash = new Uint8Array(createHash('sha256').update(rpId).digest());
  const authDataBytes = new Uint8Array(37 + 16 + 2 + credentialId.byteLength + 18);
  authDataBytes.set(rpIdHash, 0);
  authDataBytes[32] = 0x41;
  authDataBytes.set(aaguid, 37);
  const credLen = new DataView(authDataBytes.buffer, 53, 2);
  credLen.setUint16(0, credentialId.byteLength, false);
  authDataBytes.set(credentialId, 55);
  const clientDataHash = new Uint8Array(createHash('sha256').update('client-data-hash-here-32-bytes!!').digest());

  const attestedCredentialData = {
    aaguid,
    aaguidString: '00000000-0000-0000-0000-000000000000',
    credentialId,
    credentialPublicKey: coseEs256(cert.x, cert.y),
    credentialPublicKeyBytes: new Uint8Array(0),
  };
  return { authDataBytes, clientDataHash, attestedCredentialData };
}

function signPackedAttestation({ authDataBytes, clientDataHash, cert }) {
  const signed = new Uint8Array(authDataBytes.byteLength + clientDataHash.byteLength);
  signed.set(authDataBytes, 0);
  signed.set(clientDataHash, authDataBytes.byteLength);
  const sig = createSign('SHA256')
    .update(signed)
    .sign({ key: createPrivateKey(cert.keyPem), dsaEncoding: 'der' });
  return new Uint8Array(sig);
}

describe('packed attestation — self mode', () => {
  test('rejects when attStmt.alg does not match credentialPublicKey.alg', () => {
    // Credential key advertises ES256 (-7); attStmt claims RS256 (-257).
    const attStmt = new Map([
      ['alg', -257],
      ['sig', new Uint8Array([1, 2, 3])],
    ]);
    const attestedCredentialData = {
      aaguid: new Uint8Array(16),
      aaguidString: '00000000-0000-0000-0000-000000000000',
      credentialId: hex('cafeface'),
      credentialPublicKey: coseEs256(new Uint8Array(32), new Uint8Array(32)),
      credentialPublicKeyBytes: new Uint8Array(0),
    };
    assert.throws(
      () =>
        verifyPacked({
          attStmt,
          authDataBytes: new Uint8Array(37),
          clientDataHash: new Uint8Array(32),
          attestedCredentialData,
        }),
      err => err instanceof PasskeyError && err.code === ErrorCode.ATTESTATION_INVALID,
    );
  });
});

describe('packed attestation — full mode (x5c)', { skip: !HAS_OPENSSL ? 'openssl not installed' : false }, () => {
  const credentialId = hex('c0ffee');
  const aaguid = hex('00112233445566778899aabbccddeeff');

  test('verifies a well-formed packed statement', () => {
    const cert = mintPackedLeaf({
      tag: 'ok',
      subject: 'CN = Packed Test\nOU = Authenticator Attestation\nO = Passkey Test',
      aaguidExt: aaguid,
    });
    const inputs = buildPackedInputs({ rpId: 'example.com', credentialId, cert, aaguid });
    const sig = signPackedAttestation({ ...inputs, cert });
    const attStmt = new Map([
      ['alg', -7],
      ['sig', sig],
      ['x5c', [cert.der]],
    ]);
    const out = verifyPacked({ attStmt, ...inputs });
    assert.equal(out.format, 'packed');
    assert.equal(out.trustPath, 'no-anchor');
    assert.equal(out.aaguidExtensionOk, true);
  });

  test('rejects when leaf subject is missing OU=Authenticator Attestation', () => {
    const cert = mintPackedLeaf({
      tag: 'no-ou',
      subject: 'CN = Packed Test\nO = Passkey Test',
    });
    const inputs = buildPackedInputs({ rpId: 'example.com', credentialId, cert, aaguid });
    const sig = signPackedAttestation({ ...inputs, cert });
    const attStmt = new Map([
      ['alg', -7],
      ['sig', sig],
      ['x5c', [cert.der]],
    ]);
    assert.throws(
      () => verifyPacked({ attStmt, ...inputs }),
      err => err instanceof PasskeyError && err.code === ErrorCode.ATTESTATION_INVALID,
    );
  });

  test('rejects when leaf basicConstraints CA is TRUE', () => {
    const cert = mintPackedLeaf({
      tag: 'ca-true',
      subject: 'CN = Packed Test\nOU = Authenticator Attestation\nO = Passkey Test',
      ca: true,
    });
    const inputs = buildPackedInputs({ rpId: 'example.com', credentialId, cert, aaguid });
    const sig = signPackedAttestation({ ...inputs, cert });
    const attStmt = new Map([
      ['alg', -7],
      ['sig', sig],
      ['x5c', [cert.der]],
    ]);
    assert.throws(
      () => verifyPacked({ attStmt, ...inputs }),
      err => err instanceof PasskeyError && err.code === ErrorCode.ATTESTATION_INVALID,
    );
  });

  test("rejects when cert's AAGUID extension does not match authData AAGUID", () => {
    const otherAaguid = hex('ffffffffffffffffffffffffffffffff');
    const cert = mintPackedLeaf({
      tag: 'wrong-aaguid',
      subject: 'CN = Packed Test\nOU = Authenticator Attestation\nO = Passkey Test',
      aaguidExt: otherAaguid,
    });
    const inputs = buildPackedInputs({ rpId: 'example.com', credentialId, cert, aaguid });
    const sig = signPackedAttestation({ ...inputs, cert });
    const attStmt = new Map([
      ['alg', -7],
      ['sig', sig],
      ['x5c', [cert.der]],
    ]);
    assert.throws(
      () => verifyPacked({ attStmt, ...inputs }),
      err => err instanceof PasskeyError && err.code === ErrorCode.ATTESTATION_INVALID,
    );
  });

  test('trust-anchor path succeeds when the leaf is registered as an anchor', () => {
    const cert = mintPackedLeaf({
      tag: 'anchored',
      subject: 'CN = Packed Test\nOU = Authenticator Attestation\nO = Passkey Test',
      aaguidExt: aaguid,
    });
    const inputs = buildPackedInputs({ rpId: 'example.com', credentialId, cert, aaguid });
    const sig = signPackedAttestation({ ...inputs, cert });
    const attStmt = new Map([
      ['alg', -7],
      ['sig', sig],
      ['x5c', [cert.der]],
    ]);
    const out = verifyPacked({ attStmt, ...inputs, trustAnchors: [cert.pem] });
    assert.equal(out.trustPath, 'trust-anchor');
  });
});
