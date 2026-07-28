import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createPrivateKey, createSign, X509Certificate } from 'node:crypto';
import { base64url } from '@exortek/crypto/encode';
import { verifyMdsBlob, buildAaguidIndex } from '../../src/mds.js';
import { PasskeyError, ErrorCode } from '../../src/errors.js';

const OPENSSL = 'openssl';
const HAS_OPENSSL = (() => {
  try {
    execSync(`${OPENSSL} version`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

const WORK = join(tmpdir(), 'passkey-mds-tests');
if (HAS_OPENSSL && !existsSync(WORK)) {
  mkdirSync(WORK, { recursive: true });
}

/**
 * Mint a self-signed RSA cert for signing MDS blobs. Because we
 * anchor to it in the test, both roles collapse into one cert.
 */
function mintMdsSigner() {
  const keyPath = join(WORK, 'mds.key');
  const certPath = join(WORK, 'mds.pem');
  execSync(`${OPENSSL} genrsa -out ${keyPath} 2048`, { stdio: 'ignore' });
  execSync(
    `${OPENSSL} req -x509 -new -key ${keyPath} -sha256 -days 3650 -out ${certPath} -subj "/CN=FIDO MDS Signer Test"`,
    { stdio: 'ignore' },
  );
  const cert = new X509Certificate(readFileSync(certPath, 'utf8'));
  return { pem: readFileSync(certPath, 'utf8'), der: cert.raw, keyPem: readFileSync(keyPath, 'utf8') };
}

function encodeJsonB64u(obj) {
  return base64url.encode(new TextEncoder().encode(JSON.stringify(obj)));
}

function signBlob(signer, header, payload) {
  const headerB64 = encodeJsonB64u(header);
  const payloadB64 = encodeJsonB64u(payload);
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const sig = createSign('RSA-SHA256').update(signingInput).sign(createPrivateKey(signer.keyPem));
  return `${headerB64}.${payloadB64}.${base64url.encode(new Uint8Array(sig))}`;
}

describe('mds — verifyMdsBlob', { skip: !HAS_OPENSSL ? 'openssl not installed' : false }, () => {
  test('verifies a well-formed MDS3 blob', () => {
    const signer = mintMdsSigner();
    const payload = {
      legalHeader: 'test',
      no: 42,
      nextUpdate: '2126-01-01',
      entries: [
        {
          aaguid: 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4',
          metadataStatement: {
            aaguid: 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4',
            description: 'Test Authenticator',
          },
        },
      ],
    };
    const header = { alg: 'RS256', typ: 'JWT', x5c: [Buffer.from(signer.der).toString('base64')] };
    const jws = signBlob(signer, header, payload);

    const out = verifyMdsBlob(jws, { rootAnchors: [signer.pem] });
    assert.equal(out.payload.no, 42);
    assert.equal(out.payload.entries.length, 1);
    assert.equal(out.certChain.length, 1);
  });

  test('rejects a tampered signature', () => {
    const signer = mintMdsSigner();
    const header = { alg: 'RS256', x5c: [Buffer.from(signer.der).toString('base64')] };
    const payload = { no: 1, nextUpdate: '2126-01-01', entries: [] };
    let jws = signBlob(signer, header, payload);
    // Deterministically corrupt a byte deep inside the signature
    // segment. Swapping "the last character" was flaky because the
    // final base64url char often decodes to trailing bits that RSA
    // ignores, so verify still succeeded ~1 in 3 runs.
    const lastDot = jws.lastIndexOf('.');
    assert.ok(lastDot >= 0 && lastDot < jws.length - 8, 'signature segment too short to tamper');
    const chars = [...jws];
    const tamperIdx = lastDot + 4;
    chars[tamperIdx] = chars[tamperIdx] === 'A' ? '_' : 'A';
    jws = chars.join('');
    assert.throws(
      () => verifyMdsBlob(jws, { rootAnchors: [signer.pem] }),
      err => err instanceof PasskeyError && err.code === ErrorCode.MDS_BLOB_INVALID,
    );
  });

  test('rejects when rootAnchors does not cover the leaf', () => {
    const signer = mintMdsSigner();
    const other = mintMdsSigner();
    const header = { alg: 'RS256', x5c: [Buffer.from(signer.der).toString('base64')] };
    const payload = { no: 1, nextUpdate: '2126-01-01', entries: [] };
    const jws = signBlob(signer, header, payload);
    assert.throws(
      () => verifyMdsBlob(jws, { rootAnchors: [other.pem] }),
      err => err instanceof PasskeyError && err.code === ErrorCode.ATTESTATION_TRUST_ANCHOR_MISSING,
    );
  });

  test('rejects header.alg outside RS256/ES256', () => {
    const signer = mintMdsSigner();
    const header = { alg: 'HS256', x5c: [Buffer.from(signer.der).toString('base64')] };
    const payload = { no: 1, nextUpdate: '2126-01-01', entries: [] };
    const jws = signBlob(signer, header, payload);
    assert.throws(() => verifyMdsBlob(jws, { rootAnchors: [signer.pem] }), /alg must be RS256 or ES256/);
  });

  test('rejects missing rootAnchors', () => {
    assert.throws(() => verifyMdsBlob('a.b.c', {}), /rootAnchors/);
  });

  test('rejects malformed JWS', () => {
    assert.throws(() => verifyMdsBlob('not-a-jws', { rootAnchors: ['x'] }), /three segments/);
  });
});

describe('mds — buildAaguidIndex', () => {
  test('produces { aaguid: { name, statement } } map', () => {
    const idx = buildAaguidIndex({
      entries: [
        {
          aaguid: 'a-1',
          metadataStatement: { aaguid: 'a-1', description: 'Alpha' },
        },
        {
          aaguid: 'a-2',
          metadataStatement: { aaguid: 'a-2', description: 'Beta' },
        },
      ],
    });
    assert.equal(idx['a-1'].name, 'Alpha');
    assert.equal(idx['a-2'].name, 'Beta');
    assert.ok(idx['a-1'].statement);
  });

  test('skips entries without metadataStatement', () => {
    const idx = buildAaguidIndex({
      entries: [{ aaguid: 'x' }, { metadataStatement: { aaguid: 'y', description: 'Y' } }],
    });
    assert.equal(Object.keys(idx).length, 1);
    assert.ok(idx.y);
  });

  test('rejects malformed payload', () => {
    assert.throws(() => buildAaguidIndex(null), /entries/);
    assert.throws(() => buildAaguidIndex({}), /entries/);
  });
});
