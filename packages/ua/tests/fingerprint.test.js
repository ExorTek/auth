import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createFingerprint, fingerprintRequest } from '../src/fingerprint.js';

const CHROME_WIN_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
const FIREFOX_MAC_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0';

describe('createFingerprint()', () => {
  it('returns fp_ prefixed hash', () => {
    const fp = createFingerprint({ ua: CHROME_WIN_UA });
    assert.ok(fp.startsWith('fp_'));
    assert.equal(fp.length, 35); // 'fp_' + 32 hex chars
  });

  it('is deterministic', () => {
    const fp1 = createFingerprint({ ua: CHROME_WIN_UA });
    const fp2 = createFingerprint({ ua: CHROME_WIN_UA });
    assert.equal(fp1, fp2);
  });

  it('differs for different browsers', () => {
    const fp1 = createFingerprint({ ua: CHROME_WIN_UA });
    const fp2 = createFingerprint({ ua: FIREFOX_MAC_UA });
    assert.notEqual(fp1, fp2);
  });

  it('includes Accept-Language in semi-stable layer', () => {
    const fp1 = createFingerprint({
      ua: CHROME_WIN_UA,
      headers: { 'accept-language': 'en-US,en;q=0.9' },
    });
    const fp2 = createFingerprint({
      ua: CHROME_WIN_UA,
      headers: { 'accept-language': 'tr-TR,tr;q=0.9' },
    });
    assert.notEqual(fp1, fp2);
  });

  it('strict: false ignores semi-stable layer', () => {
    const fp1 = createFingerprint({ ua: CHROME_WIN_UA, headers: { 'accept-language': 'en-US' } }, { strict: false });
    const fp2 = createFingerprint({ ua: CHROME_WIN_UA, headers: { 'accept-language': 'tr-TR' } }, { strict: false });
    assert.equal(fp1, fp2);
  });

  it('includes subnet when subnet: true', () => {
    const fp1 = createFingerprint({ ua: CHROME_WIN_UA, ip: '192.168.1.100' }, { subnet: true });
    const fp2 = createFingerprint({ ua: CHROME_WIN_UA, ip: '192.168.1.200' }, { subnet: true });
    // Same /24 subnet → same fingerprint
    assert.equal(fp1, fp2);
  });

  it('different subnets produce different fingerprints', () => {
    const fp1 = createFingerprint({ ua: CHROME_WIN_UA, ip: '192.168.1.100' }, { subnet: true });
    const fp2 = createFingerprint({ ua: CHROME_WIN_UA, ip: '10.0.0.100' }, { subnet: true });
    assert.notEqual(fp1, fp2);
  });

  it('ignores IP by default', () => {
    const fp1 = createFingerprint({ ua: CHROME_WIN_UA, ip: '1.2.3.4' });
    const fp2 = createFingerprint({ ua: CHROME_WIN_UA, ip: '5.6.7.8' });
    assert.equal(fp1, fp2);
  });

  it('includes full IP when includeIP: true', () => {
    const fp1 = createFingerprint({ ua: CHROME_WIN_UA, ip: '192.168.1.100' }, { includeIP: true });
    const fp2 = createFingerprint({ ua: CHROME_WIN_UA, ip: '192.168.1.200' }, { includeIP: true });
    assert.notEqual(fp1, fp2);
  });

  it('handles IPv6 subnet', () => {
    const fp1 = createFingerprint({ ua: CHROME_WIN_UA, ip: '2001:db8:85a3:0:0:8a2e:370:7334' }, { subnet: true });
    const fp2 = createFingerprint({ ua: CHROME_WIN_UA, ip: '2001:db8:85a3:0:1:2:3:4' }, { subnet: true });
    assert.equal(fp1, fp2);
  });
});

describe('fingerprintRequest()', () => {
  it('extracts UA and IP from request object', () => {
    const req = {
      headers: { 'user-agent': CHROME_WIN_UA },
      ip: '192.168.1.1',
    };
    const fp = fingerprintRequest(req);
    assert.ok(fp.startsWith('fp_'));
  });

  it('handles missing headers gracefully', () => {
    const req = { headers: {} };
    const fp = fingerprintRequest(req);
    assert.ok(fp.startsWith('fp_'));
  });
});
