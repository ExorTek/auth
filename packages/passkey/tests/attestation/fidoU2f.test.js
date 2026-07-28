import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createSign, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { base64url } from '@exortek/crypto/encode';
import { verifyFidoU2f } from '../../src/attestation/fidoU2f.js';
import { PasskeyError, ErrorCode } from '../../src/errors.js';
import { coseEs256, hex } from '../_helpers/webauthnFixture.js';

// Fixture generated once with `openssl req -x509 -newkey ec
// -pkeyopt ec_paramgen_curve:P-256 -sha256 -days 36500 -nodes
// -subj /CN=U2F Attestation`. Valid until year 2126.

const U2F_LEAF_PEM = `-----BEGIN CERTIFICATE-----
MIIBijCCATGgAwIBAgIUZU2c2NxwTKrZ1DqKDedveETbCnwwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPVTJGIEF0dGVzdGF0aW9uMCAXDTI2MDcyODEyMDE1M1oYDzIx
MjYwNzA0MTIwMTUzWjAaMRgwFgYDVQQDDA9VMkYgQXR0ZXN0YXRpb24wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQ860Q9Wz64mSZ8pL98vKvzRQ/89WPyWM0skHfF
VLc/PrhTe72UAXd79ykfYIP5J3ZVZ6BqIoyA8LjBLt05A0OMo1MwUTAdBgNVHQ4E
FgQU3jOblB9nhzNccVRsIPxTj4mPRyEwHwYDVR0jBBgwFoAU3jOblB9nhzNccVRs
IPxTj4mPRyEwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAaL5MK
GHeoquzonQjtzv94fwq1fe5K4YmhDLL6/QvaSQIgcbvCokDfgU7bDVPCLNSLDcJU
4u8mRlyOq6HBlfaYtXQ=
-----END CERTIFICATE-----`;

const U2F_LEAF_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSoFjKE/hr3HAzcsE
m3Kuou2eG5pMif5sw65mLEssyvyhRANCAAQ860Q9Wz64mSZ8pL98vKvzRQ/89WPy
WM0skHfFVLc/PrhTe72UAXd79ykfYIP5J3ZVZ6BqIoyA8LjBLt05A0OM
-----END PRIVATE KEY-----`;

const LEAF_CERT_DER = new X509Certificate(U2F_LEAF_PEM).raw;

/**
 * Build a valid fido-u2f attestation over the four inputs. Returns
 * `{ attStmt, authDataBytes, clientDataHash, attestedCredentialData }`
 * ready to hand to `verifyFidoU2f`.
 */
function buildFidoU2f({ rpId, credentialId, x, y, corruptSig = false }) {
  const rpIdHash = new Uint8Array(createHash('sha256').update(rpId).digest());
  const clientDataHash = new Uint8Array(createHash('sha256').update('client-data-here').digest());

  // publicKeyU2F: 0x04 || x || y
  const publicKeyU2F = new Uint8Array(1 + 32 + 32);
  publicKeyU2F[0] = 0x04;
  publicKeyU2F.set(x, 1);
  publicKeyU2F.set(y, 33);

  // Signed input: 0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F
  const signed = new Uint8Array(1 + 32 + 32 + credentialId.byteLength + publicKeyU2F.byteLength);
  let pos = 0;
  signed[pos++] = 0x00;
  signed.set(rpIdHash, pos);
  pos += 32;
  signed.set(clientDataHash, pos);
  pos += 32;
  signed.set(credentialId, pos);
  pos += credentialId.byteLength;
  signed.set(publicKeyU2F, pos);

  const leafKey = createPrivateKey(U2F_LEAF_KEY_PEM);
  const sig = createSign('SHA256').update(signed).sign({ key: leafKey, dsaEncoding: 'der' });
  if (corruptSig) {
    sig[sig.length - 1] ^= 0xff;
  }

  // authData minimal shape: rpIdHash (32) || flags (1, AT set) || counter (4) ||
  // aaguid (16) || credIdLen (2) || credId || (COSE key — not read by fidoU2f).
  const flags = 0x41;
  const counter = new Uint8Array(4);
  const aaguid = new Uint8Array(16);
  const credIdLen = new Uint8Array(2);
  new DataView(credIdLen.buffer).setUint16(0, credentialId.byteLength, false);
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

  const attStmt = new Map([
    ['x5c', [LEAF_CERT_DER]],
    ['sig', new Uint8Array(sig)],
  ]);

  const attestedCredentialData = {
    aaguid,
    aaguidString: '00000000-0000-0000-0000-000000000000',
    credentialId,
    credentialPublicKey: coseEs256(x, y),
    credentialPublicKeyBytes: new Uint8Array(0),
  };

  return { attStmt, authDataBytes, clientDataHash, attestedCredentialData };
}

// The fixture leaf carries the private key we have; we need to
// use *that same key* as the "credential" for a signature that
// binds to it. Real-world: the credential key would be DIFFERENT
// from the attestation key, but the U2F verify function only
// cares that the SIGNED input includes the credential public
// key bytes, and that the sig verifies against the ATTESTATION
// leaf. So the credential key can be any P-256 point we like —
// we generate a fresh one per test.
function freshP256() {
  const kp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = kp.publicKey.export({ format: 'jwk' });
  return {
    x: new Uint8Array(base64url.decode(jwk.x)),
    y: new Uint8Array(base64url.decode(jwk.y)),
  };
}

describe('fido-u2f attestation — happy path', () => {
  test('verifies with matching x/y and correct signature', () => {
    const { x, y } = freshP256();
    const inputs = buildFidoU2f({ rpId: 'example.com', credentialId: hex('deadbeef00'), x, y });
    const out = verifyFidoU2f(inputs);
    assert.equal(out.format, 'fido-u2f');
    assert.equal(out.trustPath, 'no-anchor');
    assert.equal(out.certChain.length, 1);
  });

  test('with matching trust anchor → trust-anchor', () => {
    const { x, y } = freshP256();
    const inputs = buildFidoU2f({ rpId: 'example.com', credentialId: hex('cafebabe'), x, y });
    const out = verifyFidoU2f({ ...inputs, trustAnchors: [U2F_LEAF_PEM] });
    assert.equal(out.trustPath, 'trust-anchor');
  });
});

describe('fido-u2f attestation — rejections', () => {
  test('non-array x5c', () => {
    const { x, y } = freshP256();
    const inputs = buildFidoU2f({ rpId: 'example.com', credentialId: hex('01'), x, y });
    inputs.attStmt.set('x5c', 'not-array');
    assert.throws(
      () => verifyFidoU2f(inputs),
      err => err instanceof PasskeyError && err.code === ErrorCode.ATTESTATION_INVALID,
    );
  });

  test('multi-cert x5c (spec allows exactly one)', () => {
    const { x, y } = freshP256();
    const inputs = buildFidoU2f({ rpId: 'example.com', credentialId: hex('02'), x, y });
    inputs.attStmt.set('x5c', [LEAF_CERT_DER, LEAF_CERT_DER]);
    assert.throws(() => verifyFidoU2f(inputs), /single-element array/);
  });

  test('missing sig', () => {
    const { x, y } = freshP256();
    const inputs = buildFidoU2f({ rpId: 'example.com', credentialId: hex('03'), x, y });
    inputs.attStmt.delete('sig');
    assert.throws(() => verifyFidoU2f(inputs), /sig missing or empty/);
  });

  test('credential key not ES256 / P-256', () => {
    const { x, y } = freshP256();
    const inputs = buildFidoU2f({ rpId: 'example.com', credentialId: hex('04'), x, y });
    // Swap the credential key for something else (RS256).
    const bad = new Map();
    bad.set(1, 3);
    bad.set(3, -257);
    inputs.attestedCredentialData.credentialPublicKey = bad;
    assert.throws(() => verifyFidoU2f(inputs), /EC2 \/ ES256 \/ P-256/);
  });

  test('corrupt signature', () => {
    const { x, y } = freshP256();
    const inputs = buildFidoU2f({ rpId: 'example.com', credentialId: hex('05'), x, y, corruptSig: true });
    assert.throws(
      () => verifyFidoU2f(inputs),
      err => err instanceof PasskeyError && err.code === ErrorCode.SIGNATURE_INVALID,
    );
  });

  test('trust anchor supplied but chain unrelated → rejected', () => {
    const { x, y } = freshP256();
    const inputs = buildFidoU2f({ rpId: 'example.com', credentialId: hex('06'), x, y });
    // Use the unrelated evil cert from x509 tests as the only anchor.
    const evilPem = `-----BEGIN CERTIFICATE-----
MIIBjDCCATOgAwIBAgIUHjW0ZUMsvPrTK5SBCDC0ngmdAikwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQRXZpbCBTZWxmLVNpZ25lZDAgFw0yNjA3MjgwODI0MDZaGA8y
MTI2MDcwNDA4MjQwNlowGzEZMBcGA1UEAwwQRXZpbCBTZWxmLVNpZ25lZDBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABIjfN55bqi0kd6kdd51I5g4XX2BwcsyVIcU/
VzP4nE2/4UKX2MXqYqUA9jD6Jdp4hc5sv63FWaCbZ5WzHdxl+E6jUzBRMB0GA1Ud
DgQWBBQZJ00E1db+JMXu+Ot9pDXvfraBRDAfBgNVHSMEGDAWgBQZJ00E1db+JMXu
+Ot9pDXvfraBRDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAqZ
v62skQFrzYrq188juOtBbF50ux6Q/iJMVbRCyX6aAiAgpQfUqRtoC0bM3LplCtsy
8JonVFi7050+YMFqDtReUA==
-----END CERTIFICATE-----`;
    assert.throws(
      () => verifyFidoU2f({ ...inputs, trustAnchors: [evilPem] }),
      err => err instanceof PasskeyError && err.code === ErrorCode.ATTESTATION_TRUST_ANCHOR_MISSING,
    );
  });
});
