import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import * as crockford from '@exortek/shared/crockford';

import {
  ApiKeyError,
  ErrorCode,
  createApiKey,
  listApiKeys,
  mask,
  parseApiKey,
  rehashApiKey,
  revokeAllForUser,
  revokeApiKey,
  verifyApiKey,
} from '../src/index.js';
import { memoryStore } from '../src/stores/memory.js';

function newStore() {
  return memoryStore();
}

test('createApiKey → verifyApiKey round-trip returns valid + userId + scopes', async () => {
  const store = newStore();
  const { key, id, record } = await createApiKey({
    store,
    prefix: 'sk_live',
    userId: 'usr_1',
    scopes: ['read', 'write'],
  });
  assert.ok(key.startsWith('sk_live_'));
  assert.equal(record.id, id);
  assert.equal(record.userId, 'usr_1');
  const res = await verifyApiKey(key, { store });
  assert.equal(res.valid, true);
  if (res.valid) {
    assert.equal(res.userId, 'usr_1');
    assert.deepEqual(res.scopes, ['read', 'write']);
    assert.equal(res.prefix, 'sk_live');
  }
});

test('verify: malformed on non-strings and totally bogus input', async () => {
  const store = newStore();
  for (const input of ['', 'nope', 'sk_live', 'sk_live_only_two', null, undefined]) {
    const res = await verifyApiKey(input, { store });
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'malformed');
  }
});

test('verify: not_found for a well-shaped key that was never issued', async () => {
  const store = newStore();
  const fake = `sk_live_${crockford.encode(randomBytes(16))}_${crockford.encode(randomBytes(32))}`;
  const res = await verifyApiKey(fake, { store });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'not_found');
});

test('verify: bad_secret when id matches but secret does not', async () => {
  const store = newStore();
  const { key } = await createApiKey({ store, prefix: 'sk_live', userId: 'u', scopes: ['read'] });
  const { prefix, id } = parseApiKey(key);
  const tampered = `${prefix}_${id}_${crockford.encode(randomBytes(32))}`;
  const res = await verifyApiKey(tampered, { store });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'bad_secret');
});

test('verify: expired', async () => {
  const store = newStore();
  const { key } = await createApiKey({
    store,
    prefix: 'sk_live',
    userId: 'u',
    scopes: ['read'],
    expiresIn: '1s',
    now: 1_000_000,
  });
  const res = await verifyApiKey(key, { store, now: 1_000_000 + 5_000 });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'expired');
});

test('verify: revoked', async () => {
  const store = newStore();
  const { key } = await createApiKey({ store, prefix: 'sk_live', userId: 'u', scopes: ['read'] });
  await revokeApiKey(key, { store });
  const res = await verifyApiKey(key, { store });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'revoked');
});

test('verify: missing_scope', async () => {
  const store = newStore();
  const { key } = await createApiKey({ store, prefix: 'sk_live', userId: 'u', scopes: ['read'] });
  const res = await verifyApiKey(key, { store, requiredScopes: ['write'] });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'missing_scope');
});

test('verify: expectedPrefix mismatch', async () => {
  const store = newStore();
  const { key } = await createApiKey({ store, prefix: 'sk_live', userId: 'u', scopes: ['read'] });
  const res = await verifyApiKey(key, { store, expectedPrefix: 'sk_test' });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'prefix_mismatch');
});

test('verify: updateLastUsed bumps the record', async () => {
  const store = newStore();
  const { key, id } = await createApiKey({ store, prefix: 'sk_live', userId: 'u', scopes: ['read'] });
  const before = await store.getById(id);
  assert.equal(before.lastUsedAt, undefined);
  await verifyApiKey(key, { store, updateLastUsed: true });
  const after = await store.getById(id);
  assert.ok(after.lastUsedAt > 0);
});

test('pepper: mint + verify round-trip with a peppered secret', async () => {
  const store = newStore();
  const peppers = [randomBytes(32)];
  const { key } = await createApiKey({
    store,
    prefix: 'sk_live',
    userId: 'u',
    scopes: ['read'],
    peppers,
  });
  const ok = await verifyApiKey(key, { store, peppers });
  assert.equal(ok.valid, true);
  // Wrong pepper → bad_secret.
  const bad = await verifyApiKey(key, { store, peppers: [randomBytes(32)] });
  assert.equal(bad.valid, false);
  assert.equal(bad.reason, 'bad_secret');
});

test('pepper rotation: older-pepper match → needsRehash: true', async () => {
  const store = newStore();
  const oldPepper = randomBytes(32);
  const newPepper = randomBytes(32);
  // Mint with the old pepper as the only one.
  const { key } = await createApiKey({
    store,
    prefix: 'sk_live',
    userId: 'u',
    scopes: ['read'],
    peppers: [oldPepper],
  });
  // Now rotate — verify with new-first, old-second.
  const res = await verifyApiKey(key, { store, peppers: [newPepper, oldPepper] });
  assert.equal(res.valid, true);
  if (res.valid) {
    assert.equal(res.needsRehash, true);
  }
});

test('rehashApiKey: migrates the storage hash to the newest pepper', async () => {
  const store = newStore();
  const oldPepper = randomBytes(32);
  const newPepper = randomBytes(32);
  const { key, id } = await createApiKey({
    store,
    prefix: 'sk_live',
    userId: 'u',
    scopes: ['read'],
    peppers: [oldPepper],
  });
  const preHash = (await store.getById(id)).hash;
  await rehashApiKey(key, { store, peppers: [newPepper, oldPepper] });
  const postHash = (await store.getById(id)).hash;
  assert.notEqual(preHash, postHash);
  // Verify still works, and now without needsRehash.
  const res = await verifyApiKey(key, { store, peppers: [newPepper, oldPepper] });
  assert.equal(res.valid, true);
  if (res.valid) assert.equal(res.needsRehash, undefined);
});

test('revokeAllForUser: revokes every non-revoked key for the user', async () => {
  const store = newStore();
  const a = await createApiKey({ store, prefix: 'sk_live', userId: 'u1', scopes: ['read'] });
  const _b = await createApiKey({ store, prefix: 'sk_live', userId: 'u1', scopes: ['read'] });
  await createApiKey({ store, prefix: 'sk_live', userId: 'u2', scopes: ['read'] });
  const count = await revokeAllForUser('u1', { store });
  assert.equal(count, 2);
  assert.equal((await verifyApiKey(a.key, { store })).valid, false);
  assert.equal((await verifyApiKey(_b.key, { store })).valid, false);
});

test('listApiKeys: returns records, most-recently-used first', async () => {
  const store = newStore();
  const a = await createApiKey({ store, prefix: 'sk_live', userId: 'u', scopes: ['read'], name: 'A' });
  await createApiKey({ store, prefix: 'sk_live', userId: 'u', scopes: ['read'], name: 'B' });
  await store.update(a.id, { lastUsedAt: Date.now() + 1000 });
  const rows = await listApiKeys('u', { store });
  assert.equal(rows.length, 2);
  assert.equal(rows[0].name, 'A');
  assert.equal(rows[1].name, 'B');
});

test('invalid prefix → INVALID_ARGUMENT', async () => {
  const store = newStore();
  for (const bad of ['SK_LIVE', 'sk_live_', '_live', 'sk__live', '', 'sk-live']) {
    await assert.rejects(
      createApiKey({ store, prefix: bad, userId: 'u', scopes: ['read'] }),
      err => err instanceof ApiKeyError && err.code === ErrorCode.INVALID_ARGUMENT,
      `prefix=${JSON.stringify(bad)}`,
    );
  }
});

test('pepper < 16 bytes → INVALID_PEPPER', async () => {
  const store = newStore();
  await assert.rejects(
    createApiKey({ store, prefix: 'sk_live', userId: 'u', scopes: ['read'], peppers: [randomBytes(8)] }),
    err => err instanceof ApiKeyError && err.code === ErrorCode.INVALID_PEPPER,
  );
});

test('mask: returns log-safe display', async () => {
  const store = newStore();
  const { key, id } = await createApiKey({ store, prefix: 'sk_live', userId: 'u', scopes: ['read'] });
  const masked = mask(key);
  assert.ok(masked.startsWith(`sk_live_${id.slice(0, 6)}…`));
  assert.ok(!masked.includes(key.split('_').at(-1)));
});

test('store error inside verify → store_unavailable', async () => {
  const brokenStore = {
    async put() {},
    async getById() {
      throw new Error('down');
    },
    async update() {},
    async revoke() {},
    async revokeAllForUser() {},
    async listByUser() {
      return [];
    },
  };
  const okStore = newStore();
  const { key } = await createApiKey({ store: okStore, prefix: 'sk_live', userId: 'u', scopes: ['read'] });
  const res = await verifyApiKey(key, { store: brokenStore });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'store_unavailable');
});
