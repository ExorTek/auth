import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSessionManager } from '../src/index.js';

const SECRET = 'thirty-two-byte-secret-for-session-tests';
const mkReq = c => ({ headers: c ? { cookie: c } : {} });

test('concurrentLimit: parallel issues at limit-1 do not overrun', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    concurrentLimit: 3,
  });
  // Fill to limit-1
  await sessions.issue({ userId: 'u1' });
  await sessions.issue({ userId: 'u1' });
  // Two parallel issues — the mutex should serialise them so we end at
  // exactly `concurrentLimit` active sessions.
  await Promise.all([sessions.issue({ userId: 'u1' }), sessions.issue({ userId: 'u1' })]);
  const active = await sessions.listActive('u1');
  assert.equal(active.length, 3, `expected 3 active, got ${active.length}`);
  sessions.store._stop();
});

test('rotate: parallel rotates on the same session leave exactly one live token', async () => {
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const first = await sessions.issue({ userId: 'u1' });
  const req = mkReq(`__Host-sid=${encodeURIComponent(first.token)}`);
  const req2 = mkReq(`__Host-sid=${encodeURIComponent(first.token)}`);

  // Two parallel rotations. Under the mutex, one wins outright and the
  // second sees the record already revoked → rejects.
  const results = await Promise.allSettled([sessions.rotate(req), sessions.rotate(req2)]);
  const fulfilled = results.filter(r => r.status === 'fulfilled');
  assert.equal(fulfilled.length, 1, 'exactly one rotate should succeed');

  const active = await sessions.listActive('u1');
  assert.equal(active.length, 1, 'exactly one live session after the race');
  sessions.store._stop();
});
