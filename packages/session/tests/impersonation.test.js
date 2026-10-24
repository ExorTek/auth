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
    impersonationAuthorize: () => true,
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
    impersonationAuthorize: () => true,
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
    impersonationAuthorize: () => true,
  });
  const admin = await sessions.issue({ userId: 'admin' });
  const adminReq = mkReq(`__Host-sid=${encodeURIComponent(admin.token)}`);
  await assert.rejects(sessions.impersonate(adminReq, ''));
  sessions.store._stop();
});

test('impersonation cannot be chained from an impersonated session', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    impersonation: true,
    impersonationAuthorize: () => true,
  });
  const admin = await sessions.issue({ userId: 'admin' });
  const first = await sessions.impersonate(mkReq(`__Host-sid=${encodeURIComponent(admin.token)}`), 'victim');
  await assert.rejects(
    sessions.impersonate(mkReq(`__Host-sid=${encodeURIComponent(first.token)}`), 'other-user'),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
  sessions.store._stop();
});

test('impersonation needs an authorize hook, and the hook decides', async () => {
  assert.throws(
    () => createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m', impersonation: true }),
    err => err.code === ErrorCode.INVALID_ARGUMENT,
  );
  const seen = [];
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    impersonation: true,
    impersonationAuthorize: ({ admin, targetUserId }) => {
      seen.push([admin.userId, targetUserId]);
      return admin.userId === 'admin' && targetUserId !== 'other-admin';
    },
  });
  const user = await sessions.issue({ userId: 'regular-user' });
  await assert.rejects(
    sessions.impersonate(mkReq(`__Host-sid=${encodeURIComponent(user.token)}`), 'victim'),
    err => err instanceof SessionError && err.code === ErrorCode.FORBIDDEN,
  );
  const admin = await sessions.issue({ userId: 'admin' });
  const adminReq = mkReq(`__Host-sid=${encodeURIComponent(admin.token)}`);
  await assert.rejects(sessions.impersonate(adminReq, 'other-admin'), err => err.code === ErrorCode.FORBIDDEN);
  assert.equal((await sessions.impersonate(adminReq, 'target')).session.userId, 'target');
  assert.deepEqual(seen.at(-1), ['admin', 'target']);
  sessions.store._stop();
});

test('a per-call impersonation ttl can shorten but not extend the configured one', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    impersonation: true,
    impersonationAuthorize: () => true,
  });
  const admin = await sessions.issue({ userId: 'admin' });
  const adminReq = mkReq(`__Host-sid=${encodeURIComponent(admin.token)}`);
  await assert.rejects(
    sessions.impersonate(adminReq, 'target', { ttl: '7d' }),
    err => err.code === ErrorCode.INVALID_ARGUMENT,
  );
  await assert.rejects(
    sessions.impersonate(adminReq, 'target', { ttl: 0 }),
    err => err.code === ErrorCode.INVALID_ARGUMENT,
  );
  const short = await sessions.impersonate(adminReq, 'target', { ttl: '5m' });
  assert.ok(short.session.expiresAt - Date.now() <= 5 * 60 * 1000 + 1000);
  sessions.store._stop();
});
