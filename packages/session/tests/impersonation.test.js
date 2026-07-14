import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSessionManager, SessionError, ErrorCode } from '../src/index.js';

const SECRET = 'thirty-two-byte-secret-for-session-tests';
const mkReq = c => ({ headers: c ? { cookie: c } : {} });

test('impersonate disabled by default', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  await assert.rejects(sessions.impersonate(mkReq(), 'target'));
  sessions.store._stop();
});

test('impersonate: admin becomes target, audit trail carried', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    impersonation: true,
  });
  const admin = await sessions.issue({ userId: 'admin' });
  const adminReq = mkReq(`__Host-sid=${encodeURIComponent(admin.token)}`);
  const imp = await sessions.impersonate(adminReq, 'target-user', { reason: 'support #4211' });
  assert.equal(imp.session.userId, 'target-user');
  assert.equal(imp.session.impersonatedBy, 'admin');
  assert.equal(imp.session.impersonationReason, 'support #4211');

  // Verify the impersonation session on a separate request
  const impReq = mkReq(`__Host-sid=${encodeURIComponent(imp.token)}`);
  const verified = await sessions.verify(impReq);
  assert.equal(verified.impersonatedBy, 'admin');
  sessions.store._stop();
});

test('impersonate: rejects missing admin session', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    impersonation: true,
  });
  await assert.rejects(
    sessions.impersonate(mkReq(), 'target'),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_TOKEN,
  );
  sessions.store._stop();
});

test('impersonate: rejects missing targetUserId', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    impersonation: true,
  });
  const admin = await sessions.issue({ userId: 'admin' });
  const adminReq = mkReq(`__Host-sid=${encodeURIComponent(admin.token)}`);
  await assert.rejects(sessions.impersonate(adminReq, ''));
  sessions.store._stop();
});
