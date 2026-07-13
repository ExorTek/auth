import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSessionManager } from '../src/index.js';

const SECRET = 'thirty-two-byte-secret-for-session-tests';
const mkReq = c => ({ headers: c ? { cookie: c } : {} });

test('events: onIssue fires on issue', async () => {
  let seen = null;
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    events: {
      onIssue: session => {
        seen = session;
      },
    },
  });
  await sessions.issue({ userId: 'u1' });
  assert.ok(seen);
  assert.equal(seen.userId, 'u1');
  sessions.store._stop();
});

test('events: onVerify fires on successful verify', async () => {
  let hits = 0;
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    events: {
      onVerify: () => {
        hits += 1;
      },
    },
  });
  const { token } = await sessions.issue({ userId: 'u1' });
  const req = mkReq(`__Host-sid=${encodeURIComponent(token)}`);
  await sessions.verify(req);
  assert.equal(hits, 1);
  sessions.store._stop();
});

test('events: onRevoke fires on explicit revoke', async () => {
  const revocations = [];
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    events: {
      onRevoke: (sid, reason) => {
        revocations.push({ sid, reason });
      },
    },
  });
  const { token } = await sessions.issue({ userId: 'u1' });
  const req = mkReq(`__Host-sid=${encodeURIComponent(token)}`);
  await sessions.revoke(req, { reason: 'logout' });
  assert.equal(revocations.length, 1);
  assert.equal(revocations[0].reason, 'logout');
  sessions.store._stop();
});

test('events: onRotate carries old + new session ids', async () => {
  let payload = null;
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    events: {
      onRotate: (oldId, session) => {
        payload = { oldId, newId: session.id };
      },
    },
  });
  const first = await sessions.issue({ userId: 'u1' });
  const req = mkReq(`__Host-sid=${encodeURIComponent(first.token)}`);
  const rotated = await sessions.rotate(req);
  assert.equal(payload.oldId, first.session.id);
  assert.equal(payload.newId, rotated.session.id);
  sessions.store._stop();
});

test('events: onDeny fires on invalid token', async () => {
  const denials = [];
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    events: {
      onDeny: reason => denials.push(reason),
    },
  });
  await sessions.verify(mkReq(`__Host-sid=bogustoken`));
  assert.ok(denials.length >= 1);
  sessions.store._stop();
});

test('events: throwing handler does not break the flow', async () => {
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    events: {
      onIssue: () => {
        throw new Error('telemetry down');
      },
    },
  });
  // Issue should still succeed even though the callback threw
  const { session } = await sessions.issue({ userId: 'u1' });
  assert.equal(session.userId, 'u1');
  sessions.store._stop();
});

test('events: suspiciousActivity fires on IP change', async () => {
  const alerts = [];
  const sessions = createSessionManager({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
    bindTo: ['ua'], // bindTo captures ip on the record without invalidating on change
    suspiciousActivity: {
      onDetected: e => alerts.push(e),
    },
  });
  const issueReq = { ip: '10.0.0.1', headers: { 'user-agent': 'ua' } };
  const { token } = await sessions.issue({ userId: 'u1', req: issueReq });
  // Fingerprint only binds UA, so a different IP does not invalidate,
  // but should still fire the suspicious-activity signal.
  const laterReq = {
    ip: '10.0.0.99',
    headers: {
      cookie: `__Host-sid=${encodeURIComponent(token)}`,
      'user-agent': 'ua',
    },
  };
  await sessions.verify(laterReq);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].reason, 'ip-change');
  sessions.store._stop();
});
