import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSessionManager } from '../src/index.js';

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

test('bindStrictness soft: mismatch does not revoke, fires onSuspicious', async () => {
  const alerts = [];
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    bindTo: ['ip', 'ua'],
    bindStrictness: 'soft',
    suspiciousActivity: {
      onDetected: e => alerts.push(e),
    },
  });
  const issueReq = mkReq({ ip: '10.0.0.1', ua: 'MyBrowser/1.0' });
  const { token, session } = await sessions.issue({ userId: 'u1', req: issueReq });

  const drift = mkReq({
    cookie: `__Host-sid=${encodeURIComponent(token)}`,
    ip: '10.0.0.99',
    ua: 'MyBrowser/1.0',
  });
  const verified = await sessions.verify(drift);
  assert.ok(verified, 'soft mode keeps session alive');
  assert.equal(verified.id, session.id);
  // Two alerts: one for the fingerprint change (soft mode), one for ip-change
  // detected by the general suspicious-activity check.
  const kinds = alerts.map(a => a.reason);
  assert.ok(kinds.includes('fingerprint-mismatch'));

  // Store still has the session; not marked revoked.
  const stored = await sessions.store.get(session.id);
  assert.equal(stored.revoked, false);
  sessions.store._stop();
});

test('bindStrictness strict is default and still hard-revokes', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    bindTo: ['ip', 'ua'],
  });
  const issueReq = mkReq({ ip: '10.0.0.1', ua: 'MyBrowser/1.0' });
  const { token, session } = await sessions.issue({ userId: 'u1', req: issueReq });

  const drift = mkReq({
    cookie: `__Host-sid=${encodeURIComponent(token)}`,
    ip: '10.0.0.99',
    ua: 'MyBrowser/1.0',
  });
  assert.equal(await sessions.verify(drift), null);
  const stored = await sessions.store.get(session.id);
  assert.equal(stored.revoked, true);
  sessions.store._stop();
});

test('rejects unknown bindStrictness value', () => {
  assert.throws(() =>
    createSessionManager({
      secret: SECRET,
      ttl: '7d',
      idleTtl: '30m',
      bindStrictness: 'medium',
    }),
  );
});
