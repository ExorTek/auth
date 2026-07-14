import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSessionManager } from '../src/index.js';

const SECRET = 'thirty-two-byte-secret-for-session-tests';
const mkReq = c => ({ headers: c ? { cookie: c } : {} });

test('requireFreshAuth: never fresh right after issue', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const { token } = await sessions.issue({ userId: 'u1' });
  const req = mkReq(`__Host-sid=${encodeURIComponent(token)}`);
  assert.equal(await sessions.requireFreshAuth(req, { maxAgeSeconds: 300 }), false);
  sessions.store._stop();
});

test('markFresh → requireFreshAuth true within window', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const { token } = await sessions.issue({ userId: 'u1' });
  const req = mkReq(`__Host-sid=${encodeURIComponent(token)}`);
  await sessions.markFresh(req);
  assert.equal(await sessions.requireFreshAuth(req, { maxAgeSeconds: 300 }), true);
  sessions.store._stop();
});

test('requireFreshAuth false past the maxAgeSeconds', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const now = Date.now();
  const { token } = await sessions.issue({ userId: 'u1', now });
  const req = mkReq(`__Host-sid=${encodeURIComponent(token)}`);
  await sessions.markFresh(req, { now });
  // 400 s later, 300 s window → stale
  const later = now + 400_000;
  const req2 = mkReq(`__Host-sid=${encodeURIComponent(token)}`);
  assert.equal(await sessions.requireFreshAuth(req2, { maxAgeSeconds: 300, now: later }), false);
  sessions.store._stop();
});

test('requireFreshAuth: no session → false', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  assert.equal(await sessions.requireFreshAuth(mkReq(), { maxAgeSeconds: 300 }), false);
  sessions.store._stop();
});

test('markFresh: no session → throws', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  await assert.rejects(sessions.markFresh(mkReq()));
  sessions.store._stop();
});

test('requireFreshAuth: rejects invalid maxAgeSeconds', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  await assert.rejects(sessions.requireFreshAuth(mkReq(), { maxAgeSeconds: 0 }));
  await assert.rejects(sessions.requireFreshAuth(mkReq(), { maxAgeSeconds: -1 }));
  sessions.store._stop();
});
