import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { toCertificate, toCertificates, verifyChain } from '../../src/x509/chain.js';

// PEM fixtures generated once with OpenSSL 3.6:
//   Root CA (P-256, self-signed) → issues Intermediate (P-256, CA)
//     → issues Leaf (P-256, end-entity). Evil cert is self-signed
//     and unrelated. All valid until year 2126.

const ROOT_PEM = `-----BEGIN CERTIFICATE-----
MIIBhDCCASugAwIBAgIUc+BS6XFfU4uwsfEL9JrGu0LKDfAwCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMVGVzdCBSb290IENBMCAXDTI2MDcyODA4MjQwNloYDzIxMjYw
NzA0MDgyNDA2WjAXMRUwEwYDVQQDDAxUZXN0IFJvb3QgQ0EwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAR32iDLLiNZ3TmbY24rjkM/NmEpvB+4ffmDdc475eb6R4sC
E2Ox7Jng8/mwzRibvUClG8r2n3zIgpXNnIiMshgZo1MwUTAdBgNVHQ4EFgQUHzLr
YaK7AD/1z0Xf95gBRZMbIhowHwYDVR0jBBgwFoAUHzLrYaK7AD/1z0Xf95gBRZMb
IhowDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiArN7oD7dYIHzfE
Fl4spQEPo4HPmiIOHyHK3zgN+uhigQIgdTux7NenT58fwvabsPBINhpMSevda2I/
a6QRYK4rz2s=
-----END CERTIFICATE-----`;

const INT_PEM = `-----BEGIN CERTIFICATE-----
MIIBnDCCAUOgAwIBAgIUXtunJudw6hXUgm6ejdkwaoG2iB8wCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMVGVzdCBSb290IENBMCAXDTI2MDcyODA4MjQwNloYDzIxMjYw
NzA0MDgyNDA2WjAfMR0wGwYDVQQDDBRUZXN0IEludGVybWVkaWF0ZSBDQTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABAx+k3DWnG9kQl6+FA+JnJft297tUCWLrD74
LXXZf8512YNPeI0Mv/+SAXzyVG5oVAw/CqBzdgK3YQp/umLMOwCjYzBhMA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTDM3kevMBv3m9z
xmZ5hTonJo46NTAfBgNVHSMEGDAWgBQfMuthorsAP/XPRd/3mAFFkxsiGjAKBggq
hkjOPQQDAgNHADBEAiBsRIGKteNamXNlQVv7T6LxAYwBYkK/93l+kXts5qh0HgIg
c3GGWxb7+aMQlp+3eGmdsgq1Ebuh8RPF31wNAZN4aj0=
-----END CERTIFICATE-----`;

const LEAF_PEM = `-----BEGIN CERTIFICATE-----
MIIBeDCCAR+gAwIBAgIURlmYOGJ6671Hq0oHJ2ZGsVAwu8YwCgYIKoZIzj0EAwIw
HzEdMBsGA1UEAwwUVGVzdCBJbnRlcm1lZGlhdGUgQ0EwIBcNMjYwNzI4MDgyNDA2
WhgPMjEyNjA3MDQwODI0MDZaMBQxEjAQBgNVBAMMCVRlc3QgTGVhZjBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABApZDugNsJ7WXnV/d6v0ZTMdFuNEkQcRZZrTbgZC
Kv0M9EyzeB0T3sMDIvQNAAelP5Hq65YDxgCMwDKyABxW4u2jQjBAMB0GA1UdDgQW
BBTpMJEx+yjqGWqtJfUBfluz1AxU8zAfBgNVHSMEGDAWgBTDM3kevMBv3m9zxmZ5
hTonJo46NTAKBggqhkjOPQQDAgNHADBEAiBXc6/G/UqM8QmWy0M+owJiQ2zfGnxw
kLYLrMpngqWDnQIgWUt2KM4q8jp7qm8DLeMdjRC+OlxPbKJ1vdUgISOZPpg=
-----END CERTIFICATE-----`;

const EVIL_PEM = `-----BEGIN CERTIFICATE-----
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

const NOW = new Date('2027-01-01T00:00:00Z');

describe('x509 — toCertificate / toCertificates', () => {
  test('passes X509Certificate through', () => {
    const cert = new X509Certificate(LEAF_PEM);
    assert.strictEqual(toCertificate(cert), cert);
  });

  test('parses PEM string', () => {
    const cert = toCertificate(LEAF_PEM);
    assert.ok(cert instanceof X509Certificate);
    assert.match(cert.subject, /Test Leaf/);
  });

  test('parses DER Uint8Array', () => {
    // Strip PEM header / footer / newlines and base64-decode.
    const der = Uint8Array.from(Buffer.from(LEAF_PEM.replace(/-----.+-----/g, '').replace(/\s+/g, ''), 'base64'));
    const cert = toCertificate(der);
    assert.match(cert.subject, /Test Leaf/);
  });

  test('rejects other input types', () => {
    assert.throws(() => toCertificate(42), /expected/);
    assert.throws(() => toCertificate({}), /expected/);
  });

  test('toCertificates maps arrays', () => {
    const arr = toCertificates([LEAF_PEM, INT_PEM]);
    assert.equal(arr.length, 2);
    assert.match(arr[1].subject, /Intermediate/);
  });

  test('toCertificates rejects non-array', () => {
    assert.throws(() => toCertificates(LEAF_PEM), /expected array/);
  });
});

describe('x509 — verifyChain happy paths', () => {
  test('leaf + intermediate + root, root anchor', () => {
    verifyChain({ x5c: [LEAF_PEM, INT_PEM, ROOT_PEM], trustAnchors: [ROOT_PEM], now: NOW });
  });

  test('leaf + intermediate (no root in x5c), root anchor — issuer lookup terminates', () => {
    verifyChain({ x5c: [LEAF_PEM, INT_PEM], trustAnchors: [ROOT_PEM], now: NOW });
  });

  test('leaf + intermediate, intermediate as anchor (v13.0 behaviour)', () => {
    verifyChain({ x5c: [LEAF_PEM, INT_PEM], trustAnchors: [INT_PEM], now: NOW });
  });

  test('leaf alone, intermediate anchor', () => {
    verifyChain({ x5c: [LEAF_PEM], trustAnchors: [INT_PEM], now: NOW });
  });

  test('accepts mixed input types (PEM string, X509Certificate, Uint8Array)', () => {
    const rootDer = Uint8Array.from(Buffer.from(ROOT_PEM.replace(/-----.+-----/g, '').replace(/\s+/g, ''), 'base64'));
    const intObj = new X509Certificate(INT_PEM);
    verifyChain({ x5c: [LEAF_PEM, intObj, rootDer], trustAnchors: [ROOT_PEM], now: NOW });
  });
});

describe('x509 — verifyChain rejections', () => {
  test('empty x5c', () => {
    assert.throws(() => verifyChain({ x5c: [], trustAnchors: [ROOT_PEM], now: NOW }), /x5c is empty/);
  });

  test('empty trustAnchors', () => {
    assert.throws(() => verifyChain({ x5c: [LEAF_PEM], trustAnchors: [], now: NOW }), /trustAnchors is empty/);
  });

  test('invalid now', () => {
    assert.throws(
      () => verifyChain({ x5c: [LEAF_PEM], trustAnchors: [ROOT_PEM], now: new Date('nope') }),
      /valid Date/,
    );
  });

  test('DN mismatch inside chain (leaf + evil-as-issuer)', () => {
    assert.throws(
      () => verifyChain({ x5c: [LEAF_PEM, EVIL_PEM], trustAnchors: [ROOT_PEM], now: NOW }),
      /not issued by/,
    );
  });

  test('no anchor terminates chain', () => {
    // Leaf + intermediate, but the RP only trusts an unrelated evil cert.
    assert.throws(
      () => verifyChain({ x5c: [LEAF_PEM, INT_PEM], trustAnchors: [EVIL_PEM], now: NOW }),
      /no trust anchor terminates chain/,
    );
  });

  test('GHSA-6hxq-p678-4hr2: self-signed cert in x5c does NOT bypass anchor set', () => {
    // Attacker crafts x5c = [evil_self_signed]. RP trust anchor set
    // does not contain it. Before the CVE fix, "self-signed → treat
    // as root → accept" was the bug. We reject.
    assert.throws(
      () => verifyChain({ x5c: [EVIL_PEM], trustAnchors: [ROOT_PEM], now: NOW }),
      /no trust anchor terminates chain/,
    );
  });

  test('validity-window enforcement — future `now` past leaf notAfter is not testable with year-2126 fixtures; validate the negative direction with a way-past `now`', () => {
    // The fixtures are valid 2026-07-28 → 2126-07-04. A `now` before
    // notBefore (say the epoch) triggers the check.
    assert.throws(
      () =>
        verifyChain({
          x5c: [LEAF_PEM, INT_PEM],
          trustAnchors: [ROOT_PEM],
          now: new Date('1970-01-01T00:00:00Z'),
        }),
      /outside validity window/,
    );
  });
});
