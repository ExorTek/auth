import { test } from 'node:test';
import assert from 'node:assert/strict';

import { customStore } from '../../src/stores/custom.js';
import { createApiKey, verifyApiKey, revokeApiKey, ApiKeyError, ErrorCode } from '../../src/index.js';

test('rejects a non-object impl', () => {
  assert.throws(
    () => customStore(null),
    err => err instanceof ApiKeyError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('rejects an impl missing a required method', () => {
  assert.throws(() => customStore({ put: () => {}, getById: () => {} }), ApiKeyError);
});

test('works end-to-end through createApiKey/verifyApiKey/revokeApiKey', async () => {
  const byId = new Map();
  const store = customStore({
    async put(record) {
      byId.set(record.id, record);
    },
    async getById(id) {
      return byId.get(id) ?? null;
    },
    async update(id, patch) {
      const existing = byId.get(id);
      if (!existing) return null;
      const next = { ...existing, ...patch };
      byId.set(id, next);
      return next;
    },
    async revoke(id, reason) {
      const existing = byId.get(id);
      if (!existing || existing.revokedAt) return false;
      existing.revokedAt = Date.now();
      existing.revokedReason = reason;
      return true;
    },
    async revokeAllForUser() {
      return 0;
    },
    async listByUser(userId) {
      return [...byId.values()].filter(r => r.userId === userId);
    },
  });

  const { key, id } = await createApiKey({ store, prefix: 'sk_live', userId: 'usr_1', scopes: ['read'] });
  const res = await verifyApiKey(key, { store });
  assert.equal(res.valid, true);
  assert.equal(res.id, id);

  assert.equal(await revokeApiKey(key, { store }), true);
  assert.equal((await verifyApiKey(key, { store })).valid, false);
});
