import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSessionManager, SessionError, ErrorCode } from '../src/index.js';

const SECRET = 'thirty-two-byte-secret-for-session-tests';
const mkReq = c => ({ headers: c ? { cookie: c } : {} });

test('rotate: new token, old token revoked, claims preserved', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const first = await sessions.issue({ userId: 'u1', claims: { role: 'user' } });
  const req = mkReq(`__Host-sid=${encodeURIComponent(first.token)}`);
  const rotated = await sessions.rotate(req);
  assert.notEqual(rotated.session.id, first.session.id);
  assert.equal(rotated.session.claims.role, 'user');
  assert.equal(rotated.previousId, first.session.id);

  // Old token no longer verifies
  const oldReq = mkReq(`__Host-sid=${encodeURIComponent(first.token)}`);
  assert.equal(await sessions.verify(oldReq), null);

  // New token verifies
  const newReq = mkReq(`__Host-sid=${encodeURIComponent(rotated.token)}`);
  const verified = await sessions.verify(newReq);
  assert.equal(verified?.id, rotated.session.id);
  sessions.store._stop();
});

test('rotate: claims override supported', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const first = await sessions.issue({ userId: 'u1', claims: { role: 'user' } });
  const req = mkReq(`__Host-sid=${encodeURIComponent(first.token)}`);
  const rotated = await sessions.rotate(req, { claims: { role: 'admin' } });
  assert.equal(rotated.session.claims.role, 'admin');
  sessions.store._stop();
});

test('rotate: absolute expiry preserved (no ttl extension)', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const first = await sessions.issue({ userId: 'u1' });
  const originalExp = first.session.expiresAt;
  const req = mkReq(`__Host-sid=${encodeURIComponent(first.token)}`);
  const rotated = await sessions.rotate(req);
  assert.equal(rotated.session.expiresAt, originalExp);
  sessions.store._stop();
});

test('rotate: no session → throws INVALID_TOKEN', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  await assert.rejects(
    sessions.rotate(mkReq()),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_TOKEN,
  );
  sessions.store._stop();
});

test('touch: bumps lastSeenAt', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const { session } = await sessions.issue({ userId: 'u1' });
  const before = (await sessions.store.get(session.id)).lastSeenAt;
  await new Promise(r => setTimeout(r, 10));
  await sessions.touch(session.id);
  const after = (await sessions.store.get(session.id)).lastSeenAt;
  assert.ok(after > before);
  sessions.store._stop();
});

test('touch: missing sid returns false', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  assert.equal(await sessions.touch('nope'), false);
  sessions.store._stop();
});
