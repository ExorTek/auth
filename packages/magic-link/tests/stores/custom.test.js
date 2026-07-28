import { test } from 'node:test';
import assert from 'node:assert/strict';

import { customStore } from '../../src/stores/custom.js';
import { createMagicLink, verifyMagicLink, listPendingForEmail, MagicLinkError, ErrorCode } from '../../src/index.js';

const SECRET = 'x'.repeat(32);

test('rejects a non-object impl', () => {
  assert.throws(
    () => customStore(null),
    err => err instanceof MagicLinkError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('rejects an impl missing a required method', () => {
  assert.throws(() => customStore({ put: () => {}, getById: () => {} }), MagicLinkError);
});

function fakeImpl() {
  const byId = new Map();
  const byEmail = new Map();
  return {
    async put(record) {
      byId.set(record.id, record);
      const set = byEmail.get(record.email) ?? new Set();
      set.add(record.id);
      byEmail.set(record.email, set);
    },
    async getById(id) {
      return byId.get(id) ?? null;
    },
    async consume(id) {
      const existing = byId.get(id);
      if (!existing || existing.consumedAt) return false;
      existing.consumedAt = Date.now();
      return true;
    },
    async listByEmail(email) {
      const ids = byEmail.get(email) ?? new Set();
      return [...ids].map(id => byId.get(id)).filter(Boolean);
    },
  };
}

test('works end-to-end through createMagicLink/verifyMagicLink', async () => {
  const store = customStore(fakeImpl());
  const { token } = await createMagicLink({
    secret: SECRET,
    email: 'user@example.com',
    baseUrl: 'https://myapp.com/auth/verify',
    expiresIn: '15m',
    store,
  });

  const res = await verifyMagicLink(token, { secret: SECRET, store });
  assert.equal(res.valid, true);
  assert.equal(res.email, 'user@example.com');
});

test('optional listByEmail is passed through for listPendingForEmail', async () => {
  const store = customStore(fakeImpl());
  await createMagicLink({
    secret: SECRET,
    email: 'user@example.com',
    baseUrl: 'https://myapp.com/auth/verify',
    expiresIn: '15m',
    store,
  });

  const pending = await listPendingForEmail('user@example.com', { store });
  assert.equal(pending.length, 1);
});

test('omitting an optional method leaves it undefined on the wrapped store', () => {
  const store = customStore({
    put: () => {},
    getById: () => null,
    consume: () => false,
  });
  assert.equal(store.listByEmail, undefined);
  assert.equal(store.revokeByEmail, undefined);
  assert.equal(store.incrRate, undefined);
});
