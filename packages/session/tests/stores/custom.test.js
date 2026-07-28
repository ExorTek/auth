import { test } from 'node:test';
import assert from 'node:assert/strict';

import { customStore } from '../../src/stores/custom.js';
import { createSessionManager, SessionError, ErrorCode } from '../../src/index.js';

const SECRET = 'thirty-two-byte-secret-for-session-tests';
const mkReq = c => ({ headers: c ? { cookie: c } : {} });

test('rejects a non-object impl', () => {
  assert.throws(
    () => customStore(null),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('rejects an impl missing a required method', () => {
  assert.throws(() => customStore({ get: () => {}, put: () => {} }), SessionError);
});

function fakeImpl() {
  const byId = new Map();
  return {
    async get(sid) {
      return byId.get(sid) ?? null;
    },
    async put(record) {
      byId.set(record.sid, record);
    },
    async update(sid, patch) {
      const existing = byId.get(sid);
      if (!existing) return null;
      const next = { ...existing, ...patch };
      byId.set(sid, next);
      return next;
    },
    async revoke(sid, reason) {
      const existing = byId.get(sid);
      if (!existing) return false;
      existing.revoked = true;
      existing.revokedReason = reason;
      return true;
    },
    async revokeAllForUser(uid) {
      let count = 0;
      for (const record of byId.values()) {
        if (record.uid === uid && !record.revoked) {
          record.revoked = true;
          count += 1;
        }
      }
      return count;
    },
    async revokeAllExcept(uid, keepSid) {
      let count = 0;
      for (const record of byId.values()) {
        if (record.uid === uid && record.sid !== keepSid && !record.revoked) {
          record.revoked = true;
          count += 1;
        }
      }
      return count;
    },
    async listByUser(uid) {
      return [...byId.values()].filter(r => r.uid === uid && !r.revoked);
    },
    async countActive(uid) {
      return [...byId.values()].filter(r => r.uid === uid && !r.revoked).length;
    },
  };
}

test('works end-to-end through issue/verify/revoke', async () => {
  const store = customStore(fakeImpl());
  const sessions = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m', store });

  const { token } = await sessions.issue({ userId: 'u1' });
  const req = mkReq(`__Host-sid=${encodeURIComponent(token)}`);

  const verified = await sessions.verify(req);
  assert.ok(verified);
  assert.equal(verified.userId, 'u1');

  await sessions.revoke(req);
  assert.equal(await sessions.verify(req), null);
});

test('omitting the optional _stop leaves it undefined on the wrapped store', () => {
  const store = customStore(fakeImpl());
  assert.equal(store._stop, undefined);
});
