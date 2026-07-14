import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSessionManager, SessionError, ErrorCode } from '../src/index.js';

const SECRET = 'thirty-two-byte-secret-for-session-tests';
const mkReq = c => ({ headers: c ? { cookie: c } : {} });

test('upgrade: attaches userId to anonymous session + merges claims', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    anonymous: true,
  });
  const anon = await sessions.issue({ userId: null, claims: { cart: ['sku-1', 'sku-2'] } });
  const req = mkReq(`__Host-sid=${encodeURIComponent(anon.token)}`);
  const upgraded = await sessions.upgrade(req, 'user-42', { mergeClaims: { role: 'user' } });
  assert.equal(upgraded.session.userId, 'user-42');
  assert.equal(upgraded.session.isAnonymous, false);
  assert.deepEqual(upgraded.session.claims.cart, ['sku-1', 'sku-2']);
  assert.equal(upgraded.session.claims.role, 'user');
  sessions.store._stop();
});

test('upgrade: rejects when session is already authenticated', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    anonymous: true,
  });
  const first = await sessions.issue({ userId: 'user-1' });
  const req = mkReq(`__Host-sid=${encodeURIComponent(first.token)}`);
  await assert.rejects(
    sessions.upgrade(req, 'user-2'),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
  sessions.store._stop();
});

test('upgrade: rejects with INVALID_TOKEN when no session on req', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    anonymous: true,
  });
  await assert.rejects(
    sessions.upgrade(mkReq(), 'user-1'),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_TOKEN,
  );
  sessions.store._stop();
});

test('upgrade: rejects missing userId', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    anonymous: true,
  });
  const anon = await sessions.issue({ userId: null });
  const req = mkReq(`__Host-sid=${encodeURIComponent(anon.token)}`);
  await assert.rejects(sessions.upgrade(req, ''));
  sessions.store._stop();
});

test('upgrade: old anonymous session is revoked', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    anonymous: true,
  });
  const anon = await sessions.issue({ userId: null });
  const req = mkReq(`__Host-sid=${encodeURIComponent(anon.token)}`);
  await sessions.upgrade(req, 'user-42');
  // The old anonymous token should no longer verify
  const oldReq = mkReq(`__Host-sid=${encodeURIComponent(anon.token)}`);
  assert.equal(await sessions.verify(oldReq), null);
  sessions.store._stop();
});
