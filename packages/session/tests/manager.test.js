import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSessionManager, SessionError, ErrorCode } from '../src/index.js';

const SECRET = 'thirty-two-byte-secret-for-session-tests';

function mkReq(cookie) {
  return { headers: cookie ? { cookie } : {} };
}

test('createSessionManager: requires secret / ttl / idleTtl', () => {
  assert.throws(() => createSessionManager({}));
  assert.throws(() => createSessionManager({ secret: SECRET }));
  assert.throws(() => createSessionManager({ secret: SECRET, ttl: '7d' }));
});

test('createSessionManager: rejects idleTtl > ttl', () => {
  assert.throws(() =>
    createSessionManager({ secret: SECRET, ttl: '1h', idleTtl: '2h' }),
  );
});

test('issue → verify roundtrip', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
  });
  const { token, cookie, session } = await sessions.issue({
    userId: 'u1',
    claims: { role: 'admin' },
  });
  assert.equal(session.userId, 'u1');
  assert.deepEqual(session.claims, { role: 'admin' });
  assert.equal(session.isAnonymous, false);
  assert.match(cookie, /^__Host-sid=/);

  const req = mkReq(`__Host-sid=${encodeURIComponent(token)}`);
  const verified = await sessions.verify(req);
  assert.ok(verified);
  assert.equal(verified.id, session.id);
  assert.equal(verified.userId, 'u1');

  sessions.store._stop();
});

test('verify: no cookie → null', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  assert.equal(await sessions.verify(mkReq()), null);
  sessions.store._stop();
});

test('verify: tampered cookie → null', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const { token } = await sessions.issue({ userId: 'u1' });
  const bad = token.slice(0, -3) + 'AAA';
  const req = mkReq(`__Host-sid=${encodeURIComponent(bad)}`);
  assert.equal(await sessions.verify(req), null);
  sessions.store._stop();
});

test('verify: revoked session → null', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const { token } = await sessions.issue({ userId: 'u1' });
  const req = mkReq(`__Host-sid=${encodeURIComponent(token)}`);
  await sessions.verify(req); // populate cache
  // Bypass cache by making a fresh request
  const req2 = mkReq(`__Host-sid=${encodeURIComponent(token)}`);
  const session = await sessions.verify(req2);
  await sessions.revokeById(session.id);
  const req3 = mkReq(`__Host-sid=${encodeURIComponent(token)}`);
  assert.equal(await sessions.verify(req3), null);
  sessions.store._stop();
});

test('verify: per-request cache prevents second decode', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const { token } = await sessions.issue({ userId: 'u1' });
  const req = mkReq(`__Host-sid=${encodeURIComponent(token)}`);
  const first = await sessions.verify(req);
  // Even if we revoke the session, the cache returns the original
  await sessions.revokeById(first.id);
  const second = await sessions.verify(req);
  assert.equal(second?.id, first.id);
  sessions.store._stop();
});

test('anonymous disabled by default', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  await assert.rejects(sessions.issue({ userId: null }));
  sessions.store._stop();
});

test('anonymous: true allows null userId', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    anonymous: true,
  });
  const { session } = await sessions.issue({ userId: null });
  assert.equal(session.userId, null);
  assert.equal(session.isAnonymous, true);
  sessions.store._stop();
});

test('revoke(req): idempotent + returns delete-cookie', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const { token } = await sessions.issue({ userId: 'u1' });
  const req = mkReq(`__Host-sid=${encodeURIComponent(token)}`);
  const first = await sessions.revoke(req);
  assert.equal(first.revoked, true);
  assert.match(first.cookie, /Max-Age=0/);
  // Second revoke with no cookie is still a delete-cookie; not an error
  const second = await sessions.revoke(mkReq());
  assert.equal(second.revoked, false);
  sessions.store._stop();
});

test('revokeAllForUser kills every session', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  await sessions.issue({ userId: 'u1' });
  await sessions.issue({ userId: 'u1' });
  await sessions.issue({ userId: 'u2' });
  const killed = await sessions.revokeAllForUser('u1', { reason: 'compromise' });
  assert.equal(killed, 2);
  const list = await sessions.listActive('u1');
  assert.equal(list.length, 0);
  const others = await sessions.listActive('u2');
  assert.equal(others.length, 1);
  sessions.store._stop();
});

test('revokeAllExceptCurrent keeps current session alive', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const a = await sessions.issue({ userId: 'u1' });
  const b = await sessions.issue({ userId: 'u1' });
  await sessions.issue({ userId: 'u1' });
  const currentReq = mkReq(`__Host-sid=${encodeURIComponent(a.token)}`);
  const killed = await sessions.revokeAllExceptCurrent(currentReq);
  assert.equal(killed, 2);
  const list = await sessions.listActive('u1');
  assert.equal(list.length, 1);
  assert.equal(list[0].id, a.session.id);
  sessions.store._stop();
});

test('listActive returns newest-first', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const first = await sessions.issue({ userId: 'u1' });
  await new Promise(r => setTimeout(r, 5));
  const second = await sessions.issue({ userId: 'u1' });
  const list = await sessions.listActive('u1');
  assert.equal(list[0].id, second.session.id);
  assert.equal(list[1].id, first.session.id);
  sessions.store._stop();
});

test('concurrentLimit: kicks oldest when limit hit', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    concurrentLimit: 2,
  });
  const a = await sessions.issue({ userId: 'u1' });
  await new Promise(r => setTimeout(r, 5));
  await sessions.issue({ userId: 'u1' });
  await new Promise(r => setTimeout(r, 5));
  await sessions.issue({ userId: 'u1' });
  const list = await sessions.listActive('u1');
  assert.equal(list.length, 2);
  const stillThere = list.some(s => s.id === a.session.id);
  assert.equal(stillThere, false, 'oldest (a) should have been kicked');
  sessions.store._stop();
});

test('rememberMe doubles the absolute TTL', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
  });
  const now = Date.now();
  const regular = await sessions.issue({ userId: 'u1', now });
  const remembered = await sessions.issue({ userId: 'u2', rememberMe: true, now });
  const regularWindow = regular.session.expiresAt - now;
  const rememberedWindow = remembered.session.expiresAt - now;
  assert.equal(rememberedWindow, regularWindow * 2);
  sessions.store._stop();
});

test('secret rotation: token minted under OLD verifies under [NEW, OLD]', async () => {
  const OLD = 'thirty-two-byte-OLD-secret-goes-here-ok';
  const NEW = 'thirty-two-byte-NEW-secret-goes-here-ok';
  const oldMgr = createSessionManager({ secret: OLD, ttl: '7d', idleTtl: '30m' });
  const { token, session } = await oldMgr.issue({ userId: 'u1' });
  oldMgr.store._stop();

  const rotated = createSessionManager({
    secret: [NEW, OLD],
    ttl: '7d',
    idleTtl: '30m',
    // Share the store so the session persists across manager instances
    store: oldMgr.store,
  });
  const req = mkReq(`__Host-sid=${encodeURIComponent(token)}`);
  const verified = await rotated.verify(req);
  assert.ok(verified);
  assert.equal(verified.id, session.id);
});

test('Bearer header takes precedence when headerToken configured', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    headerToken: {},
  });
  const { token } = await sessions.issue({ userId: 'u1' });
  const req = {
    headers: {
      authorization: `Bearer ${token}`,
    },
  };
  const verified = await sessions.verify(req);
  assert.ok(verified);
  sessions.store._stop();
});

test('bad secret shape rejected', () => {
  assert.throws(() => createSessionManager({ secret: 42, ttl: '7d', idleTtl: '30m' }));
  assert.throws(() => createSessionManager({ secret: [], ttl: '7d', idleTtl: '30m' }));
});
