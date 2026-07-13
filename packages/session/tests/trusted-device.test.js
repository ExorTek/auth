import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createTrustedDeviceCookie } from '../src/trusted-device.js';

const SECRET = 'thirty-two-byte-secret-for-trusted-device';

const mkReq = cookie => ({ headers: cookie ? { cookie } : {} });

test('issue → verify roundtrip', () => {
  const td = createTrustedDeviceCookie({ secret: SECRET, ttl: '30d' });
  const setCookie = td.issue('u1');
  const cookieVal = setCookie.match(/__Host-td=([^;]+)/)[1];
  const req = mkReq(`__Host-td=${cookieVal}`);
  assert.equal(td.verify(req, 'u1'), true);
});

test('verify: wrong user → false', () => {
  const td = createTrustedDeviceCookie({ secret: SECRET, ttl: '30d' });
  const setCookie = td.issue('u1');
  const cookieVal = setCookie.match(/__Host-td=([^;]+)/)[1];
  const req = mkReq(`__Host-td=${cookieVal}`);
  assert.equal(td.verify(req, 'u2'), false);
});

test('verify: no cookie → false', () => {
  const td = createTrustedDeviceCookie({ secret: SECRET, ttl: '30d' });
  assert.equal(td.verify(mkReq(), 'u1'), false);
});

test('verify: expired token → false', () => {
  const td = createTrustedDeviceCookie({ secret: SECRET, ttl: '30d' });
  const now = 1_000_000_000_000;
  const setCookie = td.issue('u1', { now });
  const cookieVal = setCookie.match(/__Host-td=([^;]+)/)[1];
  const req = mkReq(`__Host-td=${cookieVal}`);
  const later = now + 40 * 86_400_000;
  assert.equal(td.verify(req, 'u1', { now: later }), false);
});

test('revoke: emits delete-cookie', () => {
  const td = createTrustedDeviceCookie({ secret: SECRET, ttl: '30d' });
  const del = td.revoke();
  assert.match(del, /Max-Age=0/);
});

test('secret rotation: cookie minted under OLD verifies under [NEW, OLD]', () => {
  const OLD = 'thirty-two-byte-OLD-secret-goes-here-ok';
  const NEW = 'thirty-two-byte-NEW-secret-goes-here-ok';
  const oldTd = createTrustedDeviceCookie({ secret: OLD, ttl: '30d' });
  const setCookie = oldTd.issue('u1');
  const cookieVal = setCookie.match(/__Host-td=([^;]+)/)[1];
  const rotated = createTrustedDeviceCookie({ secret: [NEW, OLD], ttl: '30d' });
  const req = mkReq(`__Host-td=${cookieVal}`);
  assert.equal(rotated.verify(req, 'u1'), true);
});
