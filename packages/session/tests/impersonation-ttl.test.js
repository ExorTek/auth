import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSessionManager } from '../src/index.js';

const SECRET = 'thirty-two-byte-secret-for-session-tests';
const mkReq = c => ({ headers: c ? { cookie: c } : {} });

test('impersonation default TTL is 30 minutes, not 7 days', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    impersonation: true,
  });
  const now = Date.now();
  const admin = await sessions.issue({ userId: 'admin', now });
  const adminReq = mkReq(`__Host-sid=${encodeURIComponent(admin.token)}`);
  const imp = await sessions.impersonate(adminReq, 'target', { reason: 'x', now });
  const window = imp.session.expiresAt - now;
  assert.equal(window, 30 * 60 * 1000, 'impersonation TTL should default to 30 minutes');
  sessions.store._stop();
});

test('impersonationTtl config overrides the default', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    impersonation: true,
    impersonationTtl: '10m',
  });
  const now = Date.now();
  const admin = await sessions.issue({ userId: 'admin', now });
  const adminReq = mkReq(`__Host-sid=${encodeURIComponent(admin.token)}`);
  const imp = await sessions.impersonate(adminReq, 'target', { now });
  assert.equal(imp.session.expiresAt - now, 10 * 60 * 1000);
  sessions.store._stop();
});

test('impersonate options.ttl overrides both config default and defaults', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    impersonation: true,
    impersonationTtl: '30m',
  });
  const now = Date.now();
  const admin = await sessions.issue({ userId: 'admin', now });
  const adminReq = mkReq(`__Host-sid=${encodeURIComponent(admin.token)}`);
  const imp = await sessions.impersonate(adminReq, 'target', { ttl: '5m', now });
  assert.equal(imp.session.expiresAt - now, 5 * 60 * 1000);
  sessions.store._stop();
});
