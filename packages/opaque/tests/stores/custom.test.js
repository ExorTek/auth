import { test } from 'node:test';
import assert from 'node:assert/strict';

import { customStore } from '../../src/stores/custom.js';
import { create, verify, revoke, OpaqueError, ErrorCode } from '../../src/index.js';

test('rejects a non-object impl', () => {
  assert.throws(
    () => customStore(null),
    err => err instanceof OpaqueError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('rejects an impl missing a required method', () => {
  assert.throws(() => customStore({ get: () => {}, delete: () => {} }), OpaqueError);
});

test('wraps a sync implementation transparently', async () => {
  const map = new Map();
  const store = customStore({
    set: (k, v) => map.set(k, v),
    get: k => map.get(k) ?? null,
    delete: k => map.delete(k),
  });

  await store.set('hash1', { a: 1 });
  assert.deepEqual(await store.get('hash1'), { a: 1 });
  assert.equal(await store.delete('hash1'), true);
  assert.equal(await store.delete('hash1'), false);
});

test('works end-to-end through create/verify/revoke', async () => {
  const map = new Map();
  const store = customStore({
    async set(k, v) {
      map.set(k, v);
    },
    async get(k) {
      return map.get(k) ?? null;
    },
    async delete(k) {
      return map.delete(k);
    },
  });

  const { token } = await create({ format: 'hex', store, metadata: { userId: 'usr_1' } });
  assert.deepEqual(await verify(token, { store }), { valid: true, metadata: { userId: 'usr_1' } });
  await revoke(token, { store });
  assert.equal((await verify(token, { store })).valid, false);
});
