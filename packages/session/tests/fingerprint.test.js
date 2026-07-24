import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSessionManager } from '../src/index.js';
import { computeFingerprint, readIp, readUserAgent } from '../src/fingerprint.js';

const SECRET = 'thirty-two-byte-secret-for-session-tests';

function mkReq({ cookie, ip, ua } = {}) {
  return {
    ip,
    headers: {
      ...(cookie ? { cookie } : {}),
      ...(ua ? { 'user-agent': ua } : {}),
    },
  };
}

test('readIp: prefers req.ip (framework-resolved)', () => {
  assert.equal(readIp({ ip: '10.0.0.1' }), '10.0.0.1');
});

test('readIp: falls back to socket.remoteAddress', () => {
  assert.equal(readIp({ socket: { remoteAddress: '10.0.0.2' } }), '10.0.0.2');
});

test('readUserAgent: caps overly long UAs', () => {
  const big = 'A'.repeat(1000);
  const ua = readUserAgent({ headers: { 'user-agent': big } });
  assert.equal(ua.length, 512);
});

test('computeFingerprint: stable across issue/verify order', () => {
  const req = mkReq({ ip: '10.0.0.1', ua: 'MyBrowser/1.0' });
  const a = computeFingerprint(req, ['ip', 'ua']);
  const b = computeFingerprint(req, ['ua', 'ip']);
  assert.equal(a, b, 'fingerprint must be independent of bindTo order');
});

test('computeFingerprint: changes on IP change', () => {
  const r1 = mkReq({ ip: '10.0.0.1', ua: 'X' });
  const r2 = mkReq({ ip: '10.0.0.2', ua: 'X' });
  assert.notEqual(computeFingerprint(r1, ['ip', 'ua']), computeFingerprint(r2, ['ip', 'ua']));
});

test('computeFingerprint: returns undefined when nothing resolved', () => {
  assert.equal(computeFingerprint({ headers: {} }, ['ip', 'ua']), undefined);
});

test('bindTo: same fingerprint → verify passes', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    bindTo: ['ip', 'ua'],
  });
  const req = mkReq({ ip: '10.0.0.1', ua: 'MyBrowser/1.0' });
  const { token } = await sessions.issue({ userId: 'u1', req });
  const verifyReq = mkReq({
    cookie: `__Host-sid=${encodeURIComponent(token)}`,
    ip: '10.0.0.1',
    ua: 'MyBrowser/1.0',
  });
  const session = await sessions.verify(verifyReq);
  assert.ok(session);
  sessions.store._stop();
});

test('bindTo: fingerprint mismatch → session revoked and verify returns null', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    bindTo: ['ip', 'ua'],
  });
  const issueReq = mkReq({ ip: '10.0.0.1', ua: 'MyBrowser/1.0' });
  const { token, session: issued } = await sessions.issue({ userId: 'u1', req: issueReq });

  const impostor = mkReq({
    cookie: `__Host-sid=${encodeURIComponent(token)}`,
    ip: '10.0.0.99',
    ua: 'MyBrowser/1.0',
  });
  assert.equal(await sessions.verify(impostor), null);

  // Session should also be marked revoked in the store
  const stored = await sessions.store.get(issued.id);
  assert.equal(stored.revoked, true);
  sessions.store._stop();
});

test('deviceLabels: derives label from UA', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    deviceLabels: true,
  });
  const req = {
    headers: { 'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit Chrome/119.0' },
  };
  const { session } = await sessions.issue({ userId: 'u1', req });
  assert.match(session.deviceLabel ?? '', /iPhone/);
  assert.match(session.deviceLabel ?? '', /Chrome/);
  sessions.store._stop();
});

test('explicit deviceLabel overrides auto', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    deviceLabels: true,
  });
  const { session } = await sessions.issue({
    userId: 'u1',
    deviceLabel: 'Custom Label',
    req: { headers: { 'user-agent': 'anything' } },
  });
  assert.equal(session.deviceLabel, 'Custom Label');
  sessions.store._stop();
});

test('bindTo: verify rejects token without fp when bindTo is set (fail-closed)', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    bindTo: ['ip', 'ua'],
  });
  // Issue without bindTo active by using a manager without it, then verify
  // with the bindTo manager — simulates a token issued before bindTo was enabled.
  const plain = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const { token } = await plain.issue({ userId: 'u1' });

  const verifyReq = mkReq({
    cookie: `__Host-sid=${encodeURIComponent(token)}`,
    ip: '10.0.0.1',
    ua: 'MyBrowser/1.0',
  });
  assert.equal(await sessions.verify(verifyReq), null);
  sessions.store._stop();
  plain.store._stop();
});

test('bindTo: impersonate sets fp from adminReq', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    bindTo: ['ip'],
    impersonation: true,
  });
  const adminReq = mkReq({ ip: '10.0.0.1', ua: 'Admin/1.0' });
  const { token: adminToken } = await sessions.issue({ userId: 'admin1', req: adminReq });
  adminReq.headers.cookie = `__Host-sid=${encodeURIComponent(adminToken)}`;
  const { token: impToken } = await sessions.impersonate(adminReq, 'target-user');

  // Verify from same IP → OK
  const sameIpReq = mkReq({
    cookie: `__Host-sid=${encodeURIComponent(impToken)}`,
    ip: '10.0.0.1',
  });
  const result = await sessions.verify(sameIpReq);
  assert.ok(result);

  // Verify from different IP → rejected
  const diffIpReq = mkReq({
    cookie: `__Host-sid=${encodeURIComponent(impToken)}`,
    ip: '10.0.0.99',
  });
  assert.equal(await sessions.verify(diffIpReq), null);
  sessions.store._stop();
});

test('bindTo: issue without req throws INVALID_ARGUMENT (fail-closed, not silent skip)', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    bindTo: ['ip', 'ua'],
  });
  await assert.rejects(
    () => sessions.issue({ userId: 'u1' }),
    err => err.code === 'INVALID_ARGUMENT' && /bindTo.*req/.test(err.message),
  );
  sessions.store._stop();
});
